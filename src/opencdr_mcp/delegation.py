"""Secret-free identity selection; the engine independently verifies issuer and grants."""

import re
import time
from urllib.parse import parse_qsl, urlsplit


def delegated_request(method, path, body, identity, owner, prefix="", now=None):
    if identity is None:
        return method, path, body
    if body is not None and not isinstance(body, dict):
        raise ValueError("Delegated operation body must be an object")
    if (
        not isinstance(identity, dict)
        or set(identity) != {"issuer", "tenant", "subject"}
        or any(
            not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9_.:@/-]{1,128}", v)
            for v in identity.values()
        )
    ):
        raise ValueError("Identity requires exactly issuer, tenant and subject")
    if method == "GET" and path == prefix + "/status" and body is None:
        return method, path, body
    parsed = urlsplit(path)
    if parsed.path == prefix + "/delegated":
        raise ValueError("Nested identity delegation is not supported")
    query = {}
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key in query:
            raise ValueError("Duplicate delegated query parameter")
        query[key] = value
    at = int(time.time()) if now is None else now
    return (
        "POST",
        prefix + "/delegated",
        {
            "identity": {
                **identity,
                "audience": dict(owner),
                "issued_at": at,
                "expires_at": at + 60,
            },
            "operation": {
                "method": method,
                "path": parsed.path,
                "query": query,
                "body": body or {},
            },
        },
    )
