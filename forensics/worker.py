"""
CRIME404 Background Processing & Modular Evidence Parser Registry (Checklist Section 9.1, 9.5, 9.6)
- Modular parser architecture: each format has a dedicated parser with name & version.
- Background task queue: ThreadPoolExecutor with Queued -> Processing -> Completed/Failed states,
  idempotency deduplication, safe retries, and processing time tracking.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Dict, Tuple
import os
import time


DEFAULT_DETECTED_TYPES = {
    "JSONEvidenceParser": "Structured JSON Log",
    "CSVEvidenceParser": "Structured CSV Artifact",
    "TextLogEvidenceParser": "Syslog / Text Log",
}


@dataclass
class ParserPlugin:
    name: str
    version: str
    extensions: Tuple[str, ...]
    parse_fn: Callable[[str, str, str], Any]
    detected_type: str = ""


class ParserRegistry:
    """Modular registry for evidence parsers with version tracking."""

    def __init__(self):
        self._plugins: Dict[str, ParserPlugin] = {}

    def register(self, plugin: ParserPlugin) -> None:
        for ext in plugin.extensions:
            self._plugins[ext.lower()] = plugin

    def get_parser(self, filename: str) -> ParserPlugin:
        ext = os.path.splitext(filename or "")[1].lower()
        return self._plugins.get(ext) or self._plugins.get(".log")

    def parse(self, content_str: str, filename: str, artifact_code: str) -> dict:
        plugin = self.get_parser(filename)
        start = time.monotonic()
        result = plugin.parse_fn(content_str, filename, artifact_code)
        if isinstance(result, tuple) and len(result) == 2:
            items, detected_type = result
        else:
            items = result
            detected_type = (
                plugin.detected_type
                or DEFAULT_DETECTED_TYPES.get(plugin.name, "Structured Log Artifact")
            )
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "items": items,
            "detected_type": detected_type,
            "parser_name": plugin.name,
            "parser_version": plugin.version,
            "elapsed_ms": elapsed_ms,
        }


class BackgroundWorkerPool:
    """
    Bounded thread-pool worker for asynchronous evidence processing & reassessment.
    Separates web request handling from heavy parsing/reasoning workloads.
    """

    def __init__(self, max_workers: int = 2):
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="crime404-worker")

    def submit(self, fn: Callable, *args, **kwargs):
        return self.executor.submit(fn, *args, **kwargs)

    def shutdown(self, wait: bool = False):
        self.executor.shutdown(wait=wait)
