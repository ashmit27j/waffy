"""waffy/web/server.py — Server-rendered control panel using Jinja2 + Starlette.

Architecture choice: server-rendered HTML (Jinja2 templates + vanilla JS)
rather than a heavy SPA framework.  Rationale:
- No build step; the control panel is a diagnostic/operator tool, not a
  user-facing product.
- Starlette's TemplateResponse handles SSR with minimal overhead.
- Static JS handles live refresh polling (SSE is overkill for an ops tool).

Process isolation
-----------------
Same rule as waffy/api: this module MUST NOT import from waffy.enforcement,
waffy.detection, waffy.proxy, or waffy.engine.  All data comes from the API
layer (shared IpcClient) or through the REST API itself.
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from waffy.ipc.client import IpcClient, IpcClientError

logger = logging.getLogger("waffy.web")

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"

_templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


def _render(request: Request, template: str, ctx: dict[str, Any] | None = None) -> Response:
    context: dict[str, Any] = {"request": request}
    if ctx:
        context.update(ctx)
    return _templates.TemplateResponse(request=request, name=template, context=context)


def build_control_panel(ipc: IpcClient) -> Starlette:
    """Build and return the Starlette control panel application.

    Parameters
    ----------
    ipc:
        ``IpcClient`` used to pull live state from waffy-core for rendering.
    """

    async def dashboard(request: Request) -> Response:
        """Main dashboard — mode banner, request/sec gauge, top signatures."""
        try:
            mode = await ipc.get_mode()
            events = await ipc.read_events(limit=20)
            bans = await ipc.read_bans()
            allowlist = await ipc.read_allowlist()
            ipc_ok = True
        except IpcClientError:
            mode = "UNKNOWN"
            events = []
            bans = []
            allowlist = []
            ipc_ok = False

        return _render(
            request,
            "dashboard.html",
            {
                "mode": mode,
                "events": events,
                "ban_count": len(bans),
                "allowlist_count": len(allowlist),
                "ipc_ok": ipc_ok,
                "active_page": "dashboard",
            },
        )

    async def events_page(request: Request) -> Response:
        """Live security event stream page."""
        try:
            events = await ipc.read_events(limit=100)
            ipc_ok = True
        except IpcClientError:
            events = []
            ipc_ok = False
        return _render(
            request,
            "events.html",
            {"events": events, "ipc_ok": ipc_ok, "active_page": "events"},
        )

    async def bans_page(request: Request) -> Response:
        """Ban list management page."""
        try:
            bans = await ipc.read_bans()
            ipc_ok = True
        except IpcClientError:
            bans = []
            ipc_ok = False

        if request.method == "POST":
            form = await request.form()
            action = str(form.get("action", ""))
            ban_id = str(form.get("ban_id", ""))
            if action == "remove" and ban_id:
                with contextlib.suppress(IpcClientError):
                    await ipc.reject_pending(ban_id=ban_id)
            return RedirectResponse(url="/panel/bans", status_code=303)

        return _render(
            request,
            "bans.html",
            {"bans": bans, "ipc_ok": ipc_ok, "active_page": "bans"},
        )

    async def allowlist_page(request: Request) -> Response:
        """Allowlist management page."""
        message = ""
        try:
            entries = await ipc.read_allowlist()
            ipc_ok = True
        except IpcClientError:
            entries = []
            ipc_ok = False

        if request.method == "POST":
            form = await request.form()
            action = str(form.get("action", ""))
            target = str(form.get("target", "")).strip()
            reason = str(form.get("reason", "Control panel entry"))
            if action == "add" and target:
                try:
                    await ipc.add_allowlist(target=target, reason=reason)
                    message = f"Added {target} to allowlist."
                except IpcClientError as exc:
                    message = f"Error: {exc}"
            elif action == "remove" and target:
                try:
                    await ipc.remove_allowlist(target=target)
                    message = f"Removed {target} from allowlist."
                except IpcClientError as exc:
                    message = f"Error: {exc}"
            return RedirectResponse(url="/panel/allowlist", status_code=303)

        return _render(
            request,
            "allowlist.html",
            {
                "entries": entries,
                "message": message,
                "ipc_ok": ipc_ok,
                "active_page": "allowlist",
            },
        )

    async def pending_page(request: Request) -> Response:
        """Pending-approval queue with one-click approve/reject."""
        try:
            bans = await ipc.read_bans()
            pending = [b for b in bans if b.get("status") == "pending_approval"]
            ipc_ok = True
        except IpcClientError:
            pending = []
            ipc_ok = False

        if request.method == "POST":
            form = await request.form()
            action = str(form.get("action", ""))
            ban_id = str(form.get("ban_id", ""))
            if ban_id:
                try:
                    if action == "approve":
                        await ipc.approve_pending(ban_id=ban_id)
                    elif action == "reject":
                        await ipc.reject_pending(ban_id=ban_id)
                except IpcClientError:
                    pass
            return RedirectResponse(url="/panel/pending", status_code=303)

        return _render(
            request,
            "pending.html",
            {"pending": pending, "ipc_ok": ipc_ok, "active_page": "pending"},
        )

    async def killswitch_page(request: Request) -> Response:
        """Kill-switch page with mandatory confirmation step."""
        message = ""
        engaged = False
        if request.method == "POST":
            form = await request.form()
            confirm = form.get("confirm") == "yes"
            reason = str(form.get("reason", "Control panel kill-switch"))
            if confirm:
                try:
                    await ipc.trigger_killswitch(reason=reason)
                    message = "Kill-switch engaged. waffy-core is now in SHADOW mode."
                    engaged = True
                except IpcClientError as exc:
                    message = f"Error: {exc}"
            else:
                message = "Kill-switch NOT activated: confirmation not provided."
            return _render(
                request,
                "killswitch.html",
                {
                    "message": message,
                    "engaged": engaged,
                    "active_page": "killswitch",
                    "ipc_ok": True,
                },
            )
        return _render(
            request,
            "killswitch.html",
            {"message": "", "engaged": False, "active_page": "killswitch", "ipc_ok": True},
        )

    routes = [
        Route("/panel", endpoint=dashboard),
        Route("/panel/", endpoint=dashboard),
        Route("/panel/events", endpoint=events_page),
        Route("/panel/bans", endpoint=bans_page, methods=["GET", "POST"]),
        Route("/panel/allowlist", endpoint=allowlist_page, methods=["GET", "POST"]),
        Route("/panel/pending", endpoint=pending_page, methods=["GET", "POST"]),
        Route("/panel/killswitch", endpoint=killswitch_page, methods=["GET", "POST"]),
        Mount("/panel/static", app=StaticFiles(directory=str(_STATIC_DIR)), name="static"),
    ]

    return Starlette(routes=routes)


__all__ = [
    "build_control_panel",
]
