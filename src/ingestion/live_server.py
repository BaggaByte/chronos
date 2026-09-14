"""
Chronos Live Ingestion & Streaming Server (Part 2).

Provides a real-time HTTP / SSE API for receiving live logs from
Ubuntu Server (auth.log), Suricata NIDS (eve.json), and other agents,
normalizing timestamps, tagging ATT&CK techniques, and broadcasting
to connected analysts/UI clients.
"""

from __future__ import annotations

import argparse
import json
import logging
import queue
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from src.anomaly.tagger import AttackTagger
from src.normalization.utc import UTCNormalizer
from src.parsers.auth_log import AuthLogParser
from src.parsers.suricata import SuricataParser
from src.schema import ChronosEvent, SourceType

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("chronos.live_server")


class LiveIngestionHub:
    """Central processor for real-time telemetry."""

    def __init__(self, max_buffer: int = 2000):
        self.auth_parser = AuthLogParser()
        self.suricata_parser = SuricataParser()
        self.normalizer = UTCNormalizer()
        self.tagger = AttackTagger()

        self.buffer: Deque[Dict[str, Any]] = deque(maxlen=max_buffer)
        self.subscribers: List[queue.Queue] = []
        self._lock = threading.Lock()

        self.stats = {
            "total_ingested": 0,
            "auth_events": 0,
            "suricata_events": 0,
            "attack_detections": 0,
            "active_hosts": set(),
            "active_src_ips": set(),
            "start_time": datetime.now(timezone.utc).isoformat(),
        }

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=500)
        with self._lock:
            self.subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        with self._lock:
            if q in self.subscribers:
                self.subscribers.remove(q)

    def ingest_record(self, source_type: str, raw_line: str, host_override: Optional[str] = None) -> Optional[ChronosEvent]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        event: Optional[ChronosEvent] = None
        st_lower = source_type.lower()

        if "auth" in st_lower or st_lower == "auth.log":
            event = self.auth_parser.parse_line(raw_line)
        elif "suricata" in st_lower or "eve" in st_lower:
            event = self.suricata_parser.parse_line(raw_line)
        elif "windows" in st_lower or "evtx" in st_lower or "openssh" in st_lower:
            event = self.auth_parser.parse_line(raw_line)
            if event:
                event.source_type = SourceType.EVTX
        else:
            # Try suricata json first, fallback to auth
            if raw_line.startswith("{"):
                event = self.suricata_parser.parse_line(raw_line)
            else:
                event = self.auth_parser.parse_line(raw_line)

        if not event:
            return None

        if host_override and (not event.host or event.host == "unknown"):
            event.host = host_override

        # 1. Normalize UTC timestamp
        self.normalizer.normalize(event)

        # 2. Tag MITRE ATT&CK techniques
        self.tagger.tag([event])

        # 3. Update stats & buffer
        event_dict = event.to_dict()
        with self._lock:
            self.buffer.append(event_dict)
            self.stats["total_ingested"] += 1
            if event.source_type == SourceType.AUTH_LOG or source_type == "auth.log":
                self.stats["auth_events"] += 1
            elif event.source_type == SourceType.SURICATA or source_type == "suricata":
                self.stats["suricata_events"] += 1
            elif event.source_type == SourceType.EVTX or "windows" in st_lower:
                self.stats.setdefault("windows_events", 0)
                self.stats["windows_events"] += 1

            if event.attack_techniques:
                self.stats["attack_detections"] += len(event.attack_techniques)

            if event.host:
                self.stats["active_hosts"].add(event.host)
            if event.src_ip:
                self.stats["active_src_ips"].add(event.src_ip)

            # Broadcast to SSE subscribers
            dead_subs = []
            for q in self.subscribers:
                try:
                    q.put_nowait(event_dict)
                except queue.Full:
                    dead_subs.append(q)
            for q in dead_subs:
                self.subscribers.remove(q)

        return event

    def get_recent_events(self, limit: int = 100, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            events = list(self.buffer)
        if severity:
            events = [e for e in events if e.get("severity") == severity]
        return events[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_ingested": self.stats["total_ingested"],
                "auth_events": self.stats["auth_events"],
                "suricata_events": self.stats["suricata_events"],
                "attack_detections": self.stats["attack_detections"],
                "active_hosts": sorted(list(self.stats["active_hosts"])),
                "active_src_ips": sorted(list(self.stats["active_src_ips"])),
                "start_time": self.stats["start_time"],
                "buffer_size": len(self.buffer),
            }


class LiveHTTPHandler(BaseHTTPRequestHandler):
    hub: LiveIngestionHub

    def _set_headers(self, status: int = 200, content_type: str = "application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(204)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/api/live/stats":
            self._set_headers(200)
            self.wfile.write(json.dumps(self.hub.get_stats()).encode("utf-8"))

        elif path == "/api/live/events":
            limit = int(query.get("limit", [100])[0])
            sev = query.get("severity", [None])[0]
            events = self.hub.get_recent_events(limit=limit, severity=sev)
            self._set_headers(200)
            self.wfile.write(json.dumps({"count": len(events), "events": events}).encode("utf-8"))

        elif path == "/api/live/stream":
            # Server-Sent Events (SSE) stream
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            q = self.hub.subscribe()
            try:
                # Send initial connection ping
                self.wfile.write(b"event: connected\ndata: {\"status\": \"connected\"}\n\n")
                self.wfile.flush()
                while True:
                    try:
                        event_data = q.get(timeout=15.0)
                        msg = f"event: log\ndata: {json.dumps(event_data)}\n\n"
                        self.wfile.write(msg.encode("utf-8"))
                        self.wfile.flush()
                    except queue.Empty:
                        # Keep-alive heartbeat
                        self.wfile.write(b": heartbeat\n\n")
                        self.wfile.flush()
            except (ConnectionResetError, BrokenPipeError):
                pass
            finally:
                self.hub.unsubscribe(q)

        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Not Found"}).encode("utf-8"))

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path in ["/api/ingest/live", "/api/live/ingest"]:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            try:
                payload = json.loads(body)
            except Exception as e:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": f"Invalid JSON: {e}"}).encode("utf-8"))
                return

            ingested = []
            if isinstance(payload, list):
                for item in payload:
                    ev = self.hub.ingest_record(
                        source_type=item.get("source_type", "unknown"),
                        raw_line=item.get("raw_line", ""),
                        host_override=item.get("host"),
                    )
                    if ev:
                        ingested.append(ev.event_id)
            elif isinstance(payload, dict):
                ev = self.hub.ingest_record(
                    source_type=payload.get("source_type", "unknown"),
                    raw_line=payload.get("raw_line", ""),
                    host_override=payload.get("host"),
                )
                if ev:
                    ingested.append(ev.event_id)

            self._set_headers(200)
            self.wfile.write(json.dumps({"status": "ok", "ingested_count": len(ingested), "ids": ingested}).encode("utf-8"))
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Not Found"}).encode("utf-8"))

    def log_message(self, format, *args):
        # Suppress noisy heartbeat/stream logs
        return


def run_live_server(host: str = "0.0.0.0", port: int = 8000, hub: Optional[LiveIngestionHub] = None):
    if hub is None:
        hub = LiveIngestionHub()

    class BoundHandler(LiveHTTPHandler):
        pass
    BoundHandler.hub = hub

    server = HTTPServer((host, port), BoundHandler)
    logger.info(f"Chronos Live Ingestion Server running on http://{host}:{port}")
    logger.info(f"Endpoints: POST /api/ingest/live | GET /api/live/stream (SSE) | GET /api/live/stats")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down live server...")
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chronos Live Ingestion & Streaming Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host address to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on")
    args = parser.parse_args()
    run_live_server(host=args.host, port=args.port)
