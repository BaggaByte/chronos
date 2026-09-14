#!/usr/bin/env python3
"""
chronos_shipper.py - Live Telemetry Forwarder for Linux (Ubuntu / Kali).

Tails Ubuntu / Linux host logs (e.g. /var/log/auth.log) and Suricata NIDS (eve.json),
buffers events, and streams them in real-time to the Chronos Ingestion Hub.

Usage:
  sudo python3 chronos_shipper.py --server http://<CHRONOS_HOST>:8000
  sudo python3 chronos_shipper.py --server http://127.0.0.1:8000 --auth-log /var/log/auth.log --suricata-eve /var/log/suricata/eve.json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from threading import Thread, Event
from typing import List, Dict, Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("chronos.shipper")


class FileFollower:
    """Tails a single log file with logrotate / truncation handling."""

    def __init__(self, path: Path, source_type: str, hostname: str, from_start: bool = False):
        self.path = path
        self.source_type = source_type
        self.hostname = hostname
        self.from_start = from_start
        self._stop_event = Event()

    def follow(self, queue_sink: List[Dict[str, Any]], lock):
        logger.info(f"Monitoring [{self.source_type}] at {self.path}")

        while not self._stop_event.is_set():
            if not self.path.exists():
                time.sleep(1.0)
                continue

            try:
                with open(self.path, "r", encoding="utf-8", errors="replace") as f:
                    if not self.from_start:
                        f.seek(0, os.SEEK_END)

                    last_inode = os.fstat(f.fileno()).st_ino

                    while not self._stop_event.is_set():
                        line = f.readline()
                        if line:
                            clean_line = line.strip()
                            if clean_line:
                                record = {
                                    "source_type": self.source_type,
                                    "raw_line": clean_line,
                                    "host": self.hostname,
                                }
                                with lock:
                                    queue_sink.append(record)
                        else:
                            # Check if file was rotated or truncated
                            time.sleep(0.25)
                            try:
                                curr_stat = os.stat(self.path)
                                if curr_stat.st_ino != last_inode or curr_stat.st_size < f.tell():
                                    logger.info(f"Log rotation detected for {self.path}. Reopening...")
                                    break
                            except FileNotFoundError:
                                break
            except PermissionError:
                logger.error(f"Permission denied reading {self.path}. Please run with sudo.")
                time.sleep(5.0)
            except Exception as e:
                logger.warning(f"Error reading {self.path}: {e}")
                time.sleep(1.0)

    def stop(self):
        self._stop_event.set()


class ChronosShipper:
    def __init__(self, server_url: str, batch_size: int = 25, flush_interval: float = 0.5):
        self.server_url = server_url.rstrip("/") + "/api/ingest/live"
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.buffer: List[Dict[str, Any]] = []
        self._lock = __import__("threading").Lock()
        self._stop_event = Event()
        self.hostname = socket.gethostname()

    def send_batch(self, batch: List[Dict[str, Any]]) -> bool:
        if not batch:
            return True
        payload = json.dumps(batch).encode("utf-8")
        req = urllib.request.Request(
            self.server_url,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "ChronosShipper/1.0"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                if resp.status == 200:
                    return True
        except Exception as e:
            logger.error(f"Failed to ship batch of {len(batch)} logs to {self.server_url}: {e}")
        return False

    def flusher_loop(self):
        last_flush = time.time()
        while not self._stop_event.is_set():
            time.sleep(0.1)
            now = time.time()
            with self._lock:
                should_flush = len(self.buffer) >= self.batch_size or (
                    len(self.buffer) > 0 and (now - last_flush) >= self.flush_interval
                )
                if should_flush:
                    to_send = list(self.buffer)
                    self.buffer.clear()
                else:
                    to_send = []

            if to_send:
                success = self.send_batch(to_send)
                if not success:
                    # Put back unsent records at the head if server is down (up to cap)
                    with self._lock:
                        if len(self.buffer) < 500:
                            self.buffer = to_send + self.buffer
                else:
                    logger.info(f"Shipped {len(to_send)} events to Chronos Live Hub.")
                last_flush = time.time()

    def run(self, targets: List[tuple[Path, str]], from_start: bool = False):
        threads = []
        followers = []

        flusher_thread = Thread(target=self.flusher_loop, daemon=True)
        flusher_thread.start()

        for path, st in targets:
            follower = FileFollower(path, st, self.hostname, from_start=from_start)
            followers.append(follower)
            t = Thread(target=follower.follow, args=(self.buffer, self._lock), daemon=True)
            t.start()
            threads.append(t)

        logger.info(f"Chronos Shipper active! Target server: {self.server_url}")
        logger.info(f"Shipping logs for host: {self.hostname}")

        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            logger.info("Stopping shipper...")
            self._stop_event.set()
            for f in followers:
                f.stop()


def main():
    parser = argparse.ArgumentParser(description="Chronos Live Log Shipper for Linux / Ubuntu / Kali")
    parser.add_argument("--server", default="http://127.0.0.1:8000", help="Chronos live server URL")
    parser.add_argument("--auth-log", default="/var/log/auth.log", help="Path to Linux auth.log")
    parser.add_argument("--suricata-eve", default="/var/log/suricata/eve.json", help="Path to Suricata eve.json")
    parser.add_argument("--from-start", action="store_true", help="Read existing files from start instead of tailing")
    parser.add_argument("--batch-size", type=int, default=20, help="Batch size for log shipment")
    parser.add_argument("--interval", type=float, default=0.5, help="Max flush interval in seconds")

    args = parser.parse_args()

    targets = []
    auth_p = Path(args.auth_log)
    if auth_p.exists() or not sys.platform.startswith("win"):
        targets.append((auth_p, "auth.log"))

    suri_p = Path(args.suricata_eve)
    if suri_p.exists() or not sys.platform.startswith("win"):
        targets.append((suri_p, "suricata"))

    if not targets:
        logger.warning(f"Neither {args.auth_log} nor {args.suricata_eve} found. Monitoring both paths as they appear.")
        targets = [(auth_p, "auth.log"), (suri_p, "suricata")]

    shipper = ChronosShipper(
        server_url=args.server,
        batch_size=args.batch_size,
        flush_interval=args.interval,
    )
    shipper.run(targets, from_start=args.from_start)


if __name__ == "__main__":
    main()
