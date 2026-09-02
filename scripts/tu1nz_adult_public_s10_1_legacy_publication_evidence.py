#!/usr/bin/env python3
"""Verify one already-public legacy SFW Telegram post without credentials."""

from __future__ import annotations

import hashlib
import json
import sys
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


PUBLIC_URL = "https://t.me/s/tu1nz_adult_publishing"
EXPECTED_POST = "2"
EXPECTED_TEXT_SHA256 = "1e776a4a514d04749b0565a91dc8f007cd8ab4b702c027090eb91754257d9324"
MAXIMUM_BYTES = 768 * 1024


class _TelegramPage(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._div_depth = 0
        self._current_post: str | None = None
        self._capture_depth: int | None = None
        self._capture_post: str | None = None
        self._parts: list[str] = []
        self.messages: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "div":
            self._div_depth += 1
            classes = set((attributes.get("class") or "").split())
            data_post = attributes.get("data-post")
            if "tgme_widget_message" in classes and data_post is not None:
                prefix = "tu1nz_adult_publishing/"
                if data_post.startswith(prefix) and data_post.removeprefix(prefix).isdigit():
                    self._current_post = data_post.removeprefix(prefix)
            if "tgme_widget_message_text" in classes and self._current_post is not None:
                self._capture_depth = self._div_depth
                self._capture_post = self._current_post
                self._parts = []
        elif tag == "br" and self._capture_depth is not None:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag != "div":
            return
        if self._capture_depth == self._div_depth and self._capture_post is not None:
            self.messages.append((self._capture_post, "".join(self._parts).strip()))
            self._capture_depth = None
            self._capture_post = None
            self._parts = []
        self._div_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._capture_depth is not None:
            self._parts.append(data)


def _verify() -> dict[str, object]:
    request = Request(PUBLIC_URL, headers={"User-Agent": "TU1NZ-S10.1-Evidence/1"})
    try:
        with urlopen(request, timeout=10) as response:
            if response.status != 200 or response.geturl().rstrip("/") != PUBLIC_URL:
                raise ValueError("S10_1_LEGACY_PUBLICATION_HTTP_RED")
            content_type = response.headers.get_content_type()
            body = response.read(MAXIMUM_BYTES + 1)
    except (HTTPError, URLError, OSError, TimeoutError):
        raise ValueError("S10_1_LEGACY_PUBLICATION_HTTP_RED") from None
    if content_type != "text/html" or not body or len(body) > MAXIMUM_BYTES:
        raise ValueError("S10_1_LEGACY_PUBLICATION_RESPONSE_INVALID")

    page = _TelegramPage()
    try:
        page.feed(body.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ValueError):
        raise ValueError("S10_1_LEGACY_PUBLICATION_RESPONSE_INVALID") from None
    if len({post for post, _ in page.messages}) != len(page.messages):
        raise ValueError("S10_1_LEGACY_PUBLICATION_RESPONSE_INVALID")
    matches = [
        post
        for post, text in page.messages
        if hashlib.sha256(text.encode("utf-8")).hexdigest() == EXPECTED_TEXT_SHA256
    ]
    if matches != [EXPECTED_POST]:
        raise ValueError("S10_1_LEGACY_PUBLICATION_EVIDENCE_DIVERGED")
    return {
        "ok": True,
        "safe_code": "S10_1_LEGACY_PUBLICATION_EVIDENCE_GREEN",
        "provider_post_id": EXPECTED_POST,
        "public_text_sha256": EXPECTED_TEXT_SHA256,
        "matched_posts": 1,
    }


def main() -> int:
    try:
        print(json.dumps(_verify(), sort_keys=True, separators=(",", ":")))
        return 0
    except ValueError as error:
        code = str(error)
        if not code.startswith("S10_1_"):
            code = "S10_1_LEGACY_PUBLICATION_EVIDENCE_RED"
        print(json.dumps({"ok": False, "safe_code": code}, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    sys.exit(main())
