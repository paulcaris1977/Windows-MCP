# Taranis fork of Windows-MCP

Fork of [CursorTouch/Windows-MCP](https://github.com/CursorTouch/Windows-MCP) (MIT,
© 2025 Jeomon George). Changes are kept in new modules where possible so upstream
updates merge cleanly.

## What this fork adds

### Safeguards (`infrastructure/safeguards.py`)
Every tool call passes through `SafeguardMiddleware` before it reaches the desktop:

- **PowerShell**: refuses disk formatting, shadow-copy/backup deletion, `bcdedit`,
  shutdown/restart, execution-policy and Defender changes, encoded commands,
  download-and-execute (`iwr ... | iex`), local account/admin changes, event-log
  clearing, `takeown`, machine-wide registry deletion, and deleting drive roots or
  system folders.
- **FileSystem**: refuses write/copy-into/move/delete under `C:\Windows`,
  `C:\Program Files`, `C:\Program Files (x86)` and `C:\ProgramData`, on drive roots,
  and deleting or moving the user profile folder.
- **Registry**: refuses `set`/`delete` under `HKLM`, `HKCR` and `HKU`.
- **Outlook**: drafts only; `send` is refused unless enabled.
- **Audit log**: one JSON line per call in `~/.windows-mcp/audit.jsonl`
  (`ok`, `blocked` or `error`). Message bodies and file contents are logged as a
  character count only.

These are guardrails against mistakes and prompt-injected instructions, not a
sandbox: a deliberately obfuscated script can still get past pattern matching.

### Outlook tool (`tools/outlook.py`, `outlook/service.py`)
Mail and calendar through the **classic** Outlook desktop app (COM). Modes:
`search`, `read`, `draft`, `reply`, `send`, `calendar`, `folders`. The new Outlook
for Windows has no COM interface and is not supported.

### Faster, private startup
- Telemetry is **off by default** (set `ANONYMIZED_TELEMETRY=true` to opt in), and
  `posthog` is no longer imported unless telemetry is on.
- `WINDOWS_MCP_PROFILE_STARTUP=1` prints `windows-mcp: ready N.NNs after process start`
  to the server log, to measure startup on the real machine.

## Configuration

Optional `~/.windows-mcp/config.toml` (all keys optional; defaults shown):

```toml
[safeguards]
enabled = true
powershell_default_deny = true          # built-in PowerShell rules
powershell_deny = []                    # extra regexes, case-insensitive
protected_paths = ['C:\Windows', 'C:\Program Files', 'C:\Program Files (x86)', 'C:\ProgramData']
allowed_write_roots = []                # non-empty: FileSystem may write only here
protect_machine_registry = true
outlook_allow_send = false
audit_log = '~/.windows-mcp/audit.jsonl' # "" disables the audit log
```

## Install in Claude Desktop

```powershell
C:\path\to\venv\Scripts\python.exe -m pip install -U "git+https://github.com/paulcaris1977/Windows-MCP.git@taranis"
```

```json
"windows-mcp": {
  "command": "C:\\path\\to\\venv\\Scripts\\python.exe",
  "args": ["-m", "windows_mcp", "serve"]
}
```

Current upstream needs the `serve` subcommand; `python -m windows_mcp` alone only
prints usage.
