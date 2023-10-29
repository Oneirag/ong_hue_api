from __future__ import annotations

import dataclasses


@dataclasses.dataclass
class QueryConfig:
    query: str
    expected_size: int
    format: str = "csv"
    expected_filename: str = None
    variables: dict = None
