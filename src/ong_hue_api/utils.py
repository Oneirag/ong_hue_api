"""
General utility functions for impala
"""
from __future__ import annotations

import datetime
import re
import uuid
import os

import requests


def check_content_type(response, filename: str) -> None:
    """Checks that the mimetype received in the content-type header matches expected for the given filename.
    Raises ValueError if not"""
    content_type = response.headers['content-type']
    ext = filename.rsplit(".")[-1]
    expected = {"xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "csv": "application/csv"}
    if content_type != expected.get(ext):
        raise ValueError(f"Could not download query for {filename}. Received content of type: {content_type}")


def add_variables(query: str, variables: dict = None) -> str:
    if not variables:
        return query
    else:
        # Replaces all know values
        for k, v in variables.items():
            query = query.replace("${" + k + "}", str(v))
        # Checks for any other parameter not informed
        res = re.findall(r"\${(\w*)}", query)
        if res:
            raise ValueError("Error in query {query}: parameters not informed {params}".format(query=query,
                                                                                               params=", ".join(res)))
        return query


def get_filename(path: str, name: str, format: str) -> str | None:
    """Forms filename with the parts of the file. Raises ValueError and returns None if pandas and file is None"""
    extensions = dict(CSV="csv", XLS="xlsx", PANDAS="xlsx")
    path = path or os.getcwd()
    ext = extensions.get(format.upper())
    if not ext:
        raise ValueError("Invalid format code {format}. Valids are {valids}".format(format=format,
                                                                                    valids=','.join(
                                                                                        extensions.keys())))
    if not name and format.lower() in ("xls", "csv"):
        raise ValueError(f"A file name must be informed when downloading format {format}")
    # If format is pandas and no name, that means file must not be created: return None
    if format.lower() == "pandas" and name is None:
        return None
    return os.path.join(path, f"{name}.{ext}")


def handle_exceptions(f):
    def wrapper(*args, **kw):
        self = args[0]
        try:
            return f(*args, **kw)
        except PermissionError as pe:
            self.log("info", "File could not be opened. Is it already opened in another application?")
            self.log("exception", pe)
        except Exception as e:
            self.log("exception", e)

    return wrapper


def get_query_chunked(query: str, total_size: int, chunk_size: int, order_by: str = "1") -> list:
    """Creates a list of queries that chunk the query into pieces, using limit and offset"""
    if not total_size:  # If total_size is None it cannot be chunked
        return [query]
    # If query already has a limit, it cannot be chunked
    if "LIMIT" in query.upper():
        return [query]
    retval = []
    offset = 0
    if "ORDER BY" not in query.upper():
        query = query + f" order by {order_by} "
    while offset < total_size:
        chunk_end = min(offset + chunk_size, total_size)
        limit = chunk_end - offset
        retval.append(f"{query} limit {limit} offset {offset}")
        offset = chunk_end
    return retval


def remove_header(content: bytes) -> bytes | None:
    """Removes header (first line) in the given content"""
    eol = content.find(b"\n")
    if eol < 0:
        return None
    else:
        return content[eol + 1:]


def new_uuid() -> str:
    """Creates a new uuid for e.g. a snippet"""
    return str(uuid.uuid4())


def timestamp() -> int:
    """Timestamp in js format"""
    return int(datetime.datetime.now().timestamp() * 1000)


def get_csfrmiddlewaretoken(response: requests.Response, index: int = 0) -> str:
    """Returns value of the hidden input field csrfmiddlewaretoken in the response.text. By default, returns first
    match, use index to return other matches"""
    csrfmiddlewaretoken = re.findall(r"csrfmiddlewaretoken' value='(?P<last>\w+)'", response.text)
    return csrfmiddlewaretoken[index]


def is_hdfs_s3(path: str) -> bool:
    """Checks if an address is a HDFS or a S3 root"""
    valid_starts = ["/", "s3a://"]
    if not any(path.startswith(start) for start in valid_starts):
        raise ValueError(f"{path=} must start with {'or '.join(valid_starts)}")
    return True


if __name__ == '__main__':
    print(res := add_variables('select * from a where a=${a} and b=${b} and c=\"${notfound}\"',
                               dict(a=1)))
