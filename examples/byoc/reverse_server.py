"""Simple BYOC worker: reverses text (batch) and optional streaming (control + events).

Batch: The orchestrator rewrites a client call like
``POST /process/request/{capability}`` on the *orchestrator* to
``POST {registered_worker_url}/{capability}`` on the worker
(``byoc/job_orchestrator.go``: ``CapabilityUrl`` + path after ``/process/request/``).
So a capability named ``text-reversal`` is invoked as
``POST {url}/text-reversal`` with ``{"text": "..."}`` — not ``/reverse-text`` unless
you used that as the external capability name.

``POST {url}/reverse-text`` is kept for older docs; prefer matching your registered
capability name as the URL path.

Streaming (orchestrator ``POST {url}/stream/start``): the worker **subscribes** to the
Gateway→Worker **control** trickle URL by issuing ``GET {control_url}/{seq}`` (start with
``-1`` for the next segment). A bare GET to ``control_url`` without a segment index is not
valid and returns a non-JSON body — that mistake surfaces as
``json.decoder.JSONDecodeError: Expecting value``.

Events are published with ``POST {events_url}/{seq}`` (``application/json``), segment
indices starting at ``0`` (same as Go ``trickle.TricklePublisher``).
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass
from typing import Any

import requests
from flask import Flask, request, Response

app = Flask(__name__)
_LOG = logging.getLogger("byoc_reverse_text")

# stream_id -> stop event
_stream_stops: dict[str, threading.Event] = {}


@dataclass
class _EventPostState:
    next_seq: int = 0


def _trickle_insecure() -> bool:
    return os.environ.get("BYOC_INSECURE_TLS", "").strip() in ("1", "true", "yes")


def _session() -> requests.Session:
    s = requests.Session()
    s.verify = not _trickle_insecure()
    return s


def _trickle_get_json(url_base: str, idx: int, session: requests.Session) -> requests.Response:
    u = f"{url_base.rstrip('/')}/{idx}"
    # Long read timeout: control segments block until the gateway posts the next message.
    return session.get(u, timeout=(20, 600))


def _next_get_idx(resp: requests.Response) -> int:
    s = resp.headers.get("Lp-Trickle-Seq", "")
    if s == "":
        return -1
    return int(s) + 1


def _trickle_post_json(url_base: str, idx: int, payload: bytes, session: requests.Session) -> None:
    u = f"{url_base.rstrip('/')}/{idx}"
    r = session.post(
        u,
        data=payload,
        headers={"Content-Type": "application/json"},
        timeout=(20, 120),
    )
    r.raise_for_status()


def _control_loop(
    stream_id: str,
    control_url: str,
    events_url: str,
    stop: threading.Event,
) -> None:
    session = _session()
    idx: int = -1
    ev = _EventPostState()

    def publish_event(obj: dict[str, Any]) -> None:
        b = json.dumps(obj).encode()
        n = ev.next_seq
        _trickle_post_json(events_url, n, b, session)
        ev.next_seq = n + 1

    while not stop.is_set():
        try:
            resp = _trickle_get_json(control_url, idx, session)
        except requests.RequestException as e:
            _LOG.warning("Control channel GET failed url=%s idx=%s err=%s", control_url, idx, e)
            break

        if resp.status_code == 404:
            _LOG.info("Control channel 404, ending reader stream_id=%s", stream_id)
            break

        if resp.status_code == 470:
            # Segment gap: jump to latest (see go-livepeer/trickle).
            latest = resp.headers.get("Lp-Trickle-Latest")
            if latest is not None and latest != "":
                try:
                    idx = int(latest) + 1
                except ValueError:
                    idx = -1
            continue

        if resp.status_code != 200:
            _LOG.warning(
                "Control channel unexpected status=%s body=%r",
                resp.status_code,
                resp.text[:500],
            )
            idx = -1
            continue

        if _closed(resp):
            _LOG.info("Control channel closed stream_id=%s", stream_id)
            break

        idx = _next_get_idx(resp)

        raw = resp.text
        if not raw.strip():
            continue

        try:
            msg = json.loads(raw)
        except json.JSONDecodeError as e:
            _LOG.warning(
                "Control channel non-JSON segment stream_id=%s err=%s snippet=%r",
                stream_id,
                e,
                raw[:200],
            )
            continue

        if isinstance(msg, dict) and msg.get("keep") == "alive":
            continue

        if isinstance(msg, dict) and "text" in msg and isinstance(msg["text"], str):
            text = msg["text"]
            out = {
                "original": text,
                "reversed": text[::-1],
            }
            _LOG.info(
                "Processed command stream_id=%s text=%s reversed=%s",
                stream_id,
                text,
                out["reversed"],
            )
            try:
                publish_event(out)
            except requests.RequestException as e:
                _LOG.warning("Events publish failed stream_id=%s err=%s", stream_id, e)
                break


def _closed(resp: requests.Response) -> bool:
    return resp.headers.get("Lp-Trickle-Closed", "") != ""


def _reverse_text_batch() -> Response:
    content = request.get_json(silent=True) or {}
    text = content.get("text", "")
    reversed_text = text[::-1]
    return Response(
        json.dumps({"original": text, "reversed": reversed_text}),
        mimetype="application/json",
    )


# Primary path: must match the registered external capability name (e.g. register "text-reversal" → /text-reversal).
@app.route("/text-reversal", methods=["POST"])
def reverse_text_by_capability() -> Response:
    return _reverse_text_batch()


# Legacy path from early doc examples.
@app.route("/reverse-text", methods=["POST"])
def reverse_text() -> Response:
    return _reverse_text_batch()


@app.route("/stream/start", methods=["POST"])
def stream_start() -> Response:
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return Response("invalid json", status=400)

    control_url = data.get("control_url")
    events_url = data.get("events_url")
    if not control_url or not events_url:
        return Response(
            json.dumps(
                {
                    "error": "control_url and events_url required in stream/start body",
                }
            ),
            status=400,
            mimetype="application/json",
        )

    stream_id = request.headers.get("X-Stream-Id", "")
    if not stream_id:
        g = data.get("gateway_request_id")
        stream_id = g if isinstance(g, str) else "unknown"

    stop = threading.Event()
    _stream_stops[stream_id] = stop
    t = threading.Thread(
        target=_control_loop,
        name=f"control-{stream_id}",
        args=(stream_id, str(control_url), str(events_url), stop),
        daemon=True,
    )
    t.start()
    _LOG.info("stream/start stream_id=%s", stream_id)
    return Response(b"{}", status=200, mimetype="application/json")


@app.route("/stream/stop", methods=["POST"])
def stream_stop() -> Response:
    stream_id = request.headers.get("X-Stream-Id", "")
    if stream_id and stream_id in _stream_stops:
        _stream_stops[stream_id].set()
        del _stream_stops[stream_id]
        _LOG.info("stream/stop stream_id=%s", stream_id)
    return Response(b"{}", status=200, mimetype="application/json")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG if os.environ.get("LOG_LEVEL", "").upper() == "DEBUG" else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    app.run(host="0.0.0.0", port=5000)
