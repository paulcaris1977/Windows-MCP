"""Outlook tool — mail and calendar through the classic Outlook desktop app."""

from typing import Literal

from mcp.types import ToolAnnotations
from windows_mcp.desktop.utils import as_bool as _as_bool
from windows_mcp.infrastructure import with_analytics
from fastmcp import Context


def register(mcp, *, get_desktop, get_analytics):
    @mcp.tool(
        name="Outlook",
        description=(
            "Mail and calendar in the classic Outlook desktop app. Keywords: email, mail, inbox, "
            "message, reply, draft, calendar, meeting, agenda. Modes: "
            "'search' (list messages in folder, default inbox; optional query matched against "
            "subject and sender, search_body=True to include the body, unread_only, days, limit), "
            "'read' (full message by entry_id), "
            "'draft' (create a new message in Drafts: to, subject, body, optional cc, bcc, "
            "html, attachments as absolute paths), "
            "'reply' (reply draft to entry_id with body, reply_all optional), "
            "'send' (send the draft with entry_id; disabled unless the user enabled sending), "
            "'calendar' (events from start (ISO date, default today) for days_ahead days), "
            "'folders' (folder tree with item counts). "
            "folder accepts inbox, sent, drafts, deleted, junk, outbox, or a path like "
            "'Inbox/Clients'. Drafts are never sent automatically: tell the user to review them."
        ),
        annotations=ToolAnnotations(
            title="Outlook",
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=True,
        ),
    )
    @with_analytics(get_analytics(), "Outlook-Tool")
    def outlook_tool(
        mode: Literal["search", "read", "draft", "reply", "send", "calendar", "folders"],
        folder: str = "inbox",
        query: str | None = None,
        search_body: bool | str = False,
        unread_only: bool | str = False,
        days: int | None = None,
        limit: int = 20,
        entry_id: str | None = None,
        to: str | None = None,
        cc: str | None = None,
        bcc: str | None = None,
        subject: str | None = None,
        body: str | None = None,
        html: bool | str = False,
        attachments: list[str] | None = None,
        reply_all: bool | str = False,
        start: str | None = None,
        days_ahead: int = 7,
        ctx: Context = None,
    ) -> str:
        # Imported per call so servers that never use Outlook never load win32com.
        from windows_mcp import outlook

        try:
            match mode:
                case "search":
                    return outlook.search_mail(
                        folder=folder,
                        query=query,
                        unread_only=_as_bool(unread_only, "unread_only"),
                        days=days,
                        limit=max(1, min(limit, 200)),
                        search_body=_as_bool(search_body, "search_body"),
                    )
                case "read":
                    if not entry_id:
                        return "Error: entry_id is required for read mode."
                    return outlook.read_mail(entry_id)
                case "draft":
                    if not to or subject is None or body is None:
                        return "Error: to, subject and body are required for draft mode."
                    return outlook.create_draft(
                        to=to,
                        subject=subject,
                        body=body,
                        cc=cc,
                        bcc=bcc,
                        html=_as_bool(html, "html"),
                        attachments=attachments,
                    )
                case "reply":
                    if not entry_id or body is None:
                        return "Error: entry_id and body are required for reply mode."
                    return outlook.reply_draft(
                        entry_id, body, reply_all=_as_bool(reply_all, "reply_all")
                    )
                case "send":
                    if not entry_id:
                        return "Error: entry_id of a draft is required for send mode."
                    return outlook.send_draft(entry_id)
                case "calendar":
                    return outlook.list_events(
                        days_ahead=max(1, min(days_ahead, 92)), start=start, limit=limit
                    )
                case "folders":
                    return outlook.list_folders()
                case _:
                    return (
                        f'Error: Unknown mode "{mode}". Use: search, read, draft, reply, send, '
                        "calendar, folders."
                    )
        except outlook.OutlookUnavailable as e:
            return f"Error: {e}"
