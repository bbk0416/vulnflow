from __future__ import annotations

"""HTTP responses for unauthenticated browser and API requests."""

from typing import Any
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import RedirectResponse, Response


def unauthenticated_response(request: Request, context: Any) -> Response:
    accepts_html = "text/html" in request.headers.get("accept", "")
    if accepts_html and not request.url.path.startswith("/api/"):
        target = request.url.path
        if request.url.query:
            target += "?" + request.url.query
        response = RedirectResponse(
            url=f"/login?next={quote(target, safe='')}", status_code=303
        )
        session_cookie = str(context.get("AUTH_SESSION_COOKIE", "vulnflow_session"))
        if request.cookies.get(session_cookie):
            response.delete_cookie(
                session_cookie,
                path="/",
                secure=bool(context.get("COOKIE_SECURE", False)),
                samesite="strict",
            )
        return response
    return Response(
        status_code=401,
        headers={"WWW-Authenticate": 'Bearer realm="VulnFlow API"'},
    )
