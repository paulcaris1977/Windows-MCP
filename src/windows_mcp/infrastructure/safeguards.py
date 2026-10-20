"""Safeguards: refuse dangerous tool calls before they run, and audit every call.

These are guardrails against mistakes and prompt-injected instructions, not a
sandbox. A determined script can still evade pattern matching (aliases, string
building, encoded payloads), which is why encoded commands are refused outright
and why the protected-path and registry checks act on structured arguments.

Configured from the ``[safeguards]`` table of ``~/.windows-mcp/config.toml``.
"""

from __future__ import annotations

import json
import logging
import ntpath
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext

from windows_mcp.infrastructure.config import SafeguardsConfig

logger = logging.getLogger(__name__)

# Each entry: (reason, regex). Matched case-insensitively against the command.
DEFAULT_POWERSHELL_DENY: tuple[tuple[str, str], ...] = (
    (
        "disk formatting or partitioning",
        r"\b(format-volume|clear-disk|initialize-disk|remove-partition|diskpart)\b"
        r"|\bformat(\.com)?\s+[a-z]:",
    ),
    (
        "backup or shadow-copy deletion",
        r"\b(vssadmin|wbadmin)\b[^\n;|]*\bdelete\b|\bwmic\b[^\n;|]*\bshadowcopy\b[^\n;|]*\bdelete\b",
    ),
    ("boot configuration change", r"\bbcdedit\b"),
    ("free-space wipe", r"\bcipher(\.exe)?\b[^\n;|]*\s/w"),
    (
        "shutdown or restart",
        r"\b(stop-computer|restart-computer)\b|\bshutdown(\.exe)?\b[^\n;|]*\s[/-][srp]\b",
    ),
    ("execution policy change", r"\bset-executionpolicy\b"),
    ("antivirus tampering", r"\bset-mppreference\b|\badd-mppreference\b[^\n;|]*exclusion"),
    ("encoded command", r"(^|\s)-e(c|nc|ncodedcommand)?\s+[a-z0-9+/=]{16,}"),
    (
        "download-and-execute",
        r"\b(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|net\.webclient)\b"
        r"[^\n;]*\|\s*(iex|invoke-expression)\b"
        r"|\b(iex|invoke-expression)\b[^\n;]*\b(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring)\b",
    ),
    (
        "local account or administrator change",
        r"\bnet(\.exe)?\s+(user|localgroup)\b[^\n;|]*\s/(add|delete)\b"
        r"|\b(new-localuser|remove-localuser|add-localgroupmember|set-localuser)\b",
    ),
    ("event log clearing", r"\bwevtutil(\.exe)?\s+(cl|clear-log)\b|\bclear-eventlog\b"),
    ("file ownership takeover", r"\btakeown(\.exe)?\b"),
    (
        "machine-wide registry deletion",
        r"\breg(\.exe)?\s+delete\s+(hklm|hkey_local_machine|hkcr|hkey_classes_root)\b"
        r"|\b(remove-item|remove-itemproperty|ri|rp)\b[^\n;|]*\b(hklm|hkcr):",
    ),
    (
        "deletion of a drive root or system folder",
        r"\b(remove-item|rm|ri|del|erase|rd|rmdir)\b[^\n;|]*"
        r"(\b[a-z]:\\?\*?[\"']?(\s|$|;|\|)"
        r"|\b[a-z]:\\(windows|program files( \(x86\))?|programdata)\b)",
    ),
)

_REGISTRY_MACHINE_ROOTS = (
    "hklm:",
    "hkcr:",
    "hku:",
    "hkey_local_machine",
    "hkey_classes_root",
    "hkey_users",
    "registry::hkey_local_machine",
    "registry::hkey_classes_root",
    "registry::hkey_users",
)

_FILESYSTEM_WRITE_MODES = frozenset({"write", "copy", "move", "delete"})

# Argument values that hold user content; the audit log records only their size.
_REDACTED_ARGS = frozenset({"content", "body", "text", "value", "html_body"})


def _norm(path: str) -> str:
    return ntpath.normcase(ntpath.normpath(os.path.expandvars(path)))


def _is_within(path: str, root: str) -> bool:
    path, root = _norm(path), _norm(root)
    return path == root or path.startswith(root.rstrip("\\") + "\\")


def _is_drive_root(path: str) -> bool:
    return re.fullmatch(r"[a-z]:\\?", _norm(path)) is not None


def _default_desktop() -> str:
    try:
        from platformdirs import user_desktop_dir

        return user_desktop_dir()
    except Exception:
        return ntpath.join(os.path.expanduser("~"), "Desktop")


class Safeguards:
    """Pure policy decisions; no I/O except the audit log."""

    def __init__(
        self,
        config: SafeguardsConfig | None = None,
        *,
        desktop_dir: Callable[[], str] = _default_desktop,
    ) -> None:
        self.config = config or SafeguardsConfig()
        self._desktop_dir = desktop_dir
        rules = list(DEFAULT_POWERSHELL_DENY) if self.config.powershell_default_deny else []
        rules += [("custom deny rule", pattern) for pattern in self.config.powershell_deny]
        self._ps_rules = [(reason, re.compile(rx, re.IGNORECASE)) for reason, rx in rules]
        self._audit_lock = threading.Lock()

    # -- decisions -------------------------------------------------------

    def check(self, tool: str, arguments: dict[str, Any] | None) -> str | None:
        """Return why the call is refused, or None when it may run."""
        if not self.config.enabled:
            return None
        args = arguments or {}
        match tool:
            case "PowerShell":
                return self._check_powershell(str(args.get("command") or ""))
            case "FileSystem":
                return self._check_filesystem(args)
            case "Registry":
                return self._check_registry(args)
            case "Outlook":
                if args.get("mode") == "send" and not self.config.outlook_allow_send:
                    return (
                        "sending email is disabled; the message stays in Drafts for the "
                        "user to review (set safeguards.outlook_allow_send = true to allow)"
                    )
        return None

    def _check_powershell(self, command: str) -> str | None:
        for reason, rule in self._ps_rules:
            if rule.search(command):
                return f"PowerShell command refused: {reason}"
        return None

    def _resolve(self, path: str) -> str:
        path = os.path.expandvars(path)
        if not ntpath.isabs(path):
            path = ntpath.join(self._desktop_dir(), path)
        return ntpath.normpath(path)

    def _check_filesystem(self, args: dict[str, Any]) -> str | None:
        mode = args.get("mode")
        if mode not in _FILESYSTEM_WRITE_MODES:
            return None
        targets = []
        if args.get("path"):
            # copy only reads its source.
            if mode != "copy":
                targets.append(self._resolve(str(args["path"])))
        if args.get("destination"):
            targets.append(self._resolve(str(args["destination"])))
        home = os.path.expanduser("~")
        for target in targets:
            if _is_drive_root(target):
                return f"FileSystem {mode} refused: {target} is a drive root"
            if mode in ("delete", "move") and _norm(target) == _norm(home):
                return f"FileSystem {mode} refused: {target} is the user profile folder"
            for root in self.config.protected_paths:
                if root and _is_within(target, root):
                    return f"FileSystem {mode} refused: {target} is inside protected {root}"
            roots = [r for r in self.config.allowed_write_roots if r]
            if roots and not any(_is_within(target, r) for r in roots):
                return f"FileSystem {mode} refused: {target} is outside the allowed write roots"
        return None

    def _check_registry(self, args: dict[str, Any]) -> str | None:
        if not self.config.protect_machine_registry or args.get("mode") not in ("set", "delete"):
            return None
        path = str(args.get("path") or "").strip().lower()
        if path.startswith(_REGISTRY_MACHINE_ROOTS):
            return f"Registry {args['mode']} refused: machine-wide key {args.get('path')}"
        return None

    # -- audit -----------------------------------------------------------

    @staticmethod
    def _summarize(arguments: dict[str, Any] | None) -> dict[str, Any]:
        summary: dict[str, Any] = {}
        for key, value in (arguments or {}).items():
            if key in _REDACTED_ARGS and isinstance(value, str):
                summary[key] = f"<{len(value)} chars>"
            elif isinstance(value, str) and len(value) > 500:
                summary[key] = value[:500] + "..."
            else:
                summary[key] = value
        return summary

    def audit(
        self, tool: str, arguments: dict[str, Any] | None, outcome: str, detail: str | None = None
    ) -> None:
        if not self.config.audit_log:
            return
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "tool": tool,
            "outcome": outcome,
            "args": self._summarize(arguments),
        }
        if detail:
            record["detail"] = detail
        try:
            path = Path(self.config.audit_log).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(record, ensure_ascii=False, default=str)
            with self._audit_lock, path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except Exception:
            logger.warning("Could not write audit log", exc_info=True)


class SafeguardMiddleware(Middleware):
    """Refuse calls the safeguards reject and audit every call."""

    def __init__(self, safeguards: Safeguards) -> None:
        self.safeguards = safeguards

    async def on_call_tool(self, context: MiddlewareContext, call_next: Callable) -> Any:
        name = context.message.name
        arguments = getattr(context.message, "arguments", None)
        reason = self.safeguards.check(name, arguments)
        if reason:
            self.safeguards.audit(name, arguments, "blocked", reason)
            raise ToolError(f"Blocked by safeguards: {reason}")
        try:
            result = await call_next(context)
        except Exception as exc:
            self.safeguards.audit(name, arguments, "error", str(exc)[:500])
            raise
        self.safeguards.audit(name, arguments, "ok")
        return result
