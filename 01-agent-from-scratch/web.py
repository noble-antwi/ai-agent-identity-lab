"""
Ask my SIEM in the browser. The same agent and the same loop (agent.run_agent),
with a different face.

Run it (with the SSH tunnel open in another window):
    python web.py
then open the link it prints. The link carries a one-time token.

Security choices, because a web page in front of an agent is a new door:
  - It listens on 127.0.0.1 only. Nothing else on the network can reach it.
  - Every request needs the random token printed at start-up, so another web
    page open in the same browser cannot quietly make the agent run (and spend).
  - Host header pinned to 127.0.0.1 / localhost, which blocks DNS-rebinding tricks.
  - Strict Content-Security-Policy: the page may run only its own script, and
    no third-party code is loaded at all.
"""

import json
import secrets
import socket
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

import agent

HERE = Path(__file__).resolve().parent
PORT = 8765
TOKEN = secrets.token_urlsafe(24)  # New every start. Never stored anywhere.

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"  # The token never leaks in a Referer.
    return response


def check(token: str) -> None:
    if not secrets.compare_digest(token, TOKEN):
        raise HTTPException(status_code=403, detail="Missing or wrong token. Use the link web.py printed.")


@app.get("/")
def page(token: str = ""):
    check(token)
    return FileResponse(HERE / "static" / "index.html")


@app.get("/health")
def health(token: str = ""):
    """Is the tunnel up? A plain connection test: no login, no data."""
    check(token)
    try:
        with socket.create_connection(("127.0.0.1", 9200), timeout=1):
            tunnel = True
    except OSError:
        tunnel = False
    return {"tunnel": tunnel, "model": agent.MODEL}


@app.get("/ask")
def ask(q: str = Query(min_length=3, max_length=500), token: str = ""):
    check(token)

    def events():
        try:
            for event in agent.run_agent(q):
                if event["type"] == "tool_result" and not event["is_error"]:
                    # Send the page the parsed result so it can draw it.
                    event = {"type": "tool_result", "is_error": False,
                             "result": json.loads(event["output"]),
                             "characters": len(event["output"])}
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as e:  # Any failure is shown, never swallowed.
            yield f"data: {json.dumps({'type': 'error', 'message': f'{type(e).__name__}: {e}'})}\n\n"
        yield f"data: {json.dumps({'type': 'done'})}\n\n"

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache"})


if __name__ == "__main__":
    print("\n  Ask my SIEM is running on this laptop only. Open this link:\n")
    print(f"  http://127.0.0.1:{PORT}/?token={TOKEN}\n")
    print("  Press Ctrl+C here to stop it.\n", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
