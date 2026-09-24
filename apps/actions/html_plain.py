"""Derive readable plain text from HTML for multipart email."""

from __future__ import annotations

import html2text


def html_to_plain_text(html: str) -> str:
    converter = html2text.HTML2Text()
    converter.body_width = 0
    converter.ignore_images = True
    converter.ignore_emphasis = False
    converter.protect_links = True
    converter.single_line_break = False
    converter.unicode_snob = True
    plain = converter.handle(html or '')
    return plain.strip()
