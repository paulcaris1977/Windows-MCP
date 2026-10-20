"""Outlook service: mail and calendar through the classic Outlook desktop COM API.

The new Outlook for Windows (olk.exe) has no COM automation interface; every
call fails with ``OutlookUnavailable`` there.

Each public function opens its own COM apartment because tools run on generic
worker threads, and Outlook objects must not cross threads.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Iterator

from tabulate import tabulate

logger = logging.getLogger(__name__)

# OlDefaultFolders
FOLDER_IDS = {
    "inbox": 6,
    "sent": 5,
    "drafts": 16,
    "deleted": 3,
    "outbox": 4,
    "junk": 23,
    "calendar": 9,
}
OL_MAIL_ITEM = 0
OL_MAIL_CLASS = 43
OL_FORMAT_HTML = 2

MAX_SCAN = 2000  # Items examined per search; bounds latency on large folders.
MAX_BODY_CHARS = 20000


class OutlookUnavailable(RuntimeError):
    pass


@contextmanager
def _outlook() -> Iterator[Any]:
    import pythoncom
    import win32com.client

    initialized = False
    try:
        pythoncom.CoInitialize()
        initialized = True
    except pythoncom.com_error:
        pass  # Thread already has an apartment; Outlook is out-of-process either way.
    try:
        try:
            app = win32com.client.Dispatch("Outlook.Application")
            namespace = app.GetNamespace("MAPI")
        except pythoncom.com_error as exc:
            raise OutlookUnavailable(
                "Classic Outlook is not available through COM. This tool needs the classic "
                "Outlook desktop app (the new Outlook for Windows has no automation API)."
            ) from exc
        yield namespace
    finally:
        if initialized:
            pythoncom.CoUninitialize()


def _local(dt: Any) -> datetime:
    """pywin32 tags Outlook's local times as UTC; drop the tzinfo, keep the wall time."""
    return datetime(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)


def _fmt(dt: Any) -> str:
    return _local(dt).strftime("%Y-%m-%d %H:%M")


def _jet_date(dt: datetime) -> str:
    """Format *dt* the way Outlook parses Jet date literals: the user's short date and time."""
    import ctypes
    from ctypes import wintypes

    st = wintypes.WORD * 8
    system_time = st(dt.year, dt.month, dt.isoweekday() % 7, dt.day, dt.hour, dt.minute, 0, 0)
    kernel32 = ctypes.windll.kernel32
    date_buf = ctypes.create_unicode_buffer(80)
    time_buf = ctypes.create_unicode_buffer(80)
    # LOCALE_NAME_USER_DEFAULT (None), DATE_SHORTDATE = 1, TIME_NOSECONDS = 2
    kernel32.GetDateFormatEx(None, 1, ctypes.byref(system_time), None, date_buf, 80, None)
    kernel32.GetTimeFormatEx(None, 2, ctypes.byref(system_time), None, time_buf, 80)
    return f"{date_buf.value} {time_buf.value}"


def _dasl_quote(text: str) -> str:
    return text.replace("'", "''")


def _search_filter(query: str, search_body: bool) -> str:
    q = _dasl_quote(query)
    fields = [
        "urn:schemas:httpmail:subject",
        "urn:schemas:httpmail:fromname",
        "urn:schemas:httpmail:fromemail",
    ]
    if search_body:
        fields.append("urn:schemas:httpmail:textdescription")
    clauses = " OR ".join(f"\"{f}\" LIKE '%{q}%'" for f in fields)
    return f"@SQL=({clauses})"


def _folder(namespace: Any, folder: str) -> Any:
    key = folder.strip().lower()
    if key in FOLDER_IDS:
        return namespace.GetDefaultFolder(FOLDER_IDS[key])
    # A path such as "Inbox/Clients/IDL", resolved from the default store's root.
    parts = [p for p in folder.replace("\\", "/").split("/") if p]
    current = namespace.GetDefaultFolder(FOLDER_IDS["inbox"]).Parent
    for part in parts:
        match = next(
            (f for f in current.Folders if f.Name.lower() == part.lower()),
            None,
        )
        if match is None:
            raise ValueError(f"Folder not found: {folder!r} (missing {part!r})")
        current = match
    return current


def _sender(item: Any) -> str:
    try:
        address = item.SenderEmailAddress or ""
        if item.SenderEmailType == "EX":
            exchange_user = item.Sender.GetExchangeUser()
            if exchange_user is not None:
                address = exchange_user.PrimarySmtpAddress
    except Exception:
        address = ""
    name = getattr(item, "SenderName", "") or ""
    return f"{name} <{address}>" if address and address != name else name


def search_mail(
    folder: str = "inbox",
    query: str | None = None,
    unread_only: bool = False,
    days: int | None = None,
    limit: int = 20,
    search_body: bool = False,
) -> str:
    with _outlook() as ns:
        items = _folder(ns, folder).Items
        if query:
            items = items.Restrict(_search_filter(query, search_body))
        if unread_only:
            items = items.Restrict("[UnRead] = True")
        sort_field = (
            "[SentOn]" if folder.strip().lower() in ("sent", "drafts") else "[ReceivedTime]"
        )
        items.Sort(sort_field, True)
        cutoff = datetime.now() - timedelta(days=days) if days else None

        rows = []
        item = items.GetFirst()
        scanned = 0
        while item is not None and len(rows) < limit and scanned < MAX_SCAN:
            scanned += 1
            if getattr(item, "Class", None) == OL_MAIL_CLASS:
                when = item.ReceivedTime if sort_field == "[ReceivedTime]" else item.SentOn
                if cutoff and _local(when) < cutoff:
                    break
                rows.append(
                    [
                        _fmt(when),
                        _sender(item),
                        item.Subject or "(no subject)",
                        "yes" if item.UnRead else "",
                        item.EntryID,
                    ]
                )
            item = items.GetNext()
    if not rows:
        return "No matching messages."
    return tabulate(rows, headers=["Date", "From", "Subject", "Unread", "EntryID"])


def read_mail(entry_id: str, max_chars: int = MAX_BODY_CHARS) -> str:
    with _outlook() as ns:
        item = ns.GetItemFromID(entry_id)
        body = item.Body or ""
        if len(body) > max_chars:
            body = body[:max_chars] + f"\n... [truncated, {len(item.Body)} chars total]"
        attachments = [
            item.Attachments.Item(i).FileName for i in range(1, item.Attachments.Count + 1)
        ]
        when = item.ReceivedTime if getattr(item, "ReceivedTime", None) else item.CreationTime
        lines = [
            f"From: {_sender(item)}",
            f"To: {item.To or ''}",
            f"Cc: {item.CC or ''}",
            f"Date: {_fmt(when)}",
            f"Subject: {item.Subject or ''}",
            f"Attachments: {', '.join(attachments) if attachments else 'none'}",
            f"EntryID: {item.EntryID}",
            "",
            body,
        ]
    return "\n".join(lines)


def create_draft(
    to: str,
    subject: str,
    body: str,
    cc: str | None = None,
    bcc: str | None = None,
    html: bool = False,
    attachments: list[str] | None = None,
) -> str:
    with _outlook() as ns:
        mail = ns.Application.CreateItem(OL_MAIL_ITEM)
        mail.To = to
        if cc:
            mail.CC = cc
        if bcc:
            mail.BCC = bcc
        mail.Subject = subject
        if html:
            mail.BodyFormat = OL_FORMAT_HTML
            mail.HTMLBody = body
        else:
            mail.Body = body
        for path in attachments or []:
            mail.Attachments.Add(path)
        mail.Save()
        return f"Draft saved in Drafts. EntryID: {mail.EntryID}"


def reply_draft(entry_id: str, body: str, reply_all: bool = False) -> str:
    with _outlook() as ns:
        original = ns.GetItemFromID(entry_id)
        reply = original.ReplyAll() if reply_all else original.Reply()
        if reply.BodyFormat == OL_FORMAT_HTML:
            escaped = (
                body.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\n", "<br>")
            )
            reply.HTMLBody = f"<div>{escaped}</div><br>" + reply.HTMLBody
        else:
            reply.Body = body + "\n\n" + reply.Body
        reply.Save()
        return f"Reply draft saved in Drafts (to: {reply.To}). EntryID: {reply.EntryID}"


def send_draft(entry_id: str) -> str:
    with _outlook() as ns:
        item = ns.GetItemFromID(entry_id)
        if getattr(item, "Sent", False):
            return "Error: this message has already been sent."
        subject, to = item.Subject, item.To
        item.Send()
        return f"Sent '{subject}' to {to}."


def list_events(days_ahead: int = 7, start: str | None = None, limit: int = 50) -> str:
    begin = (
        datetime.fromisoformat(start)
        if start
        else datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    )
    end = begin + timedelta(days=days_ahead)
    with _outlook() as ns:
        items = ns.GetDefaultFolder(FOLDER_IDS["calendar"]).Items
        # Order matters: recurrences expand only with IncludeRecurrences set after sorting.
        items.Sort("[Start]")
        items.IncludeRecurrences = True
        restricted = items.Restrict(
            f"[Start] < '{_jet_date(end)}' AND [End] > '{_jet_date(begin)}'"
        )
        rows = []
        item = restricted.GetFirst()
        while item is not None and len(rows) < limit:
            item_start = _local(item.Start)
            if item_start >= end:
                break
            if _local(item.End) > begin:
                rows.append(
                    [
                        item_start.strftime("%a %Y-%m-%d %H:%M"),
                        _local(item.End).strftime("%H:%M"),
                        item.Subject or "(no subject)",
                        item.Location or "",
                        item.Organizer or "",
                    ]
                )
            item = restricted.GetNext()
    if not rows:
        return f"No events between {begin:%Y-%m-%d} and {end:%Y-%m-%d}."
    return tabulate(rows, headers=["Start", "End", "Subject", "Location", "Organizer"])


def list_folders(depth: int = 2) -> str:
    lines: list[str] = []

    def walk(folder: Any, level: int) -> None:
        if level > depth:
            return
        for sub in folder.Folders:
            lines.append(f"{'  ' * level}{sub.Name} ({sub.Items.Count})")
            walk(sub, level + 1)

    with _outlook() as ns:
        for store in ns.Stores:
            lines.append(f"[{store.DisplayName}]")
            walk(store.GetRootFolder(), 1)
    return "\n".join(lines)
