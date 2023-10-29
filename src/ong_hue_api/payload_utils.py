"""
Functions to create an url-encoded payload from a dictionary or a list of tuples
"""
from __future__ import annotations

import json
import urllib.parse


def format_payload_qsl(qsl: list | tuple) -> str:
    return urllib.parse.urlencode(qsl, safe="*")


def format_payload(**kwargs) -> str:
    qsl = []
    for k, v in kwargs.items():
        qsl.append((k, v if isinstance(v, str) else json.dumps(v, separators=(',', ':'))))
    return format_payload_qsl(qsl)
