from dataclasses import dataclass
from typing import List
from urllib.parse import urljoin


SAFE_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}


@dataclass
class NormalizedEndpoint:
    method: str
    route: str
    url: str


def normalize_api_list(api_base_url: str, raw_api_list: str) -> List[NormalizedEndpoint]:
    endpoints = []
    base = (api_base_url or "").rstrip("/") + "/"

    for raw_line in (raw_api_list or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        parts = line.split(maxsplit=1)
        if len(parts) == 1:
            method, route = "GET", parts[0]
        else:
            method, route = parts[0].upper(), parts[1]

        if method not in SAFE_METHODS:
            method = "GET"

        if not route.startswith("/"):
            route = f"/{route}"

        endpoints.append(NormalizedEndpoint(method=method, route=route, url=urljoin(base, route.lstrip("/"))))

    return endpoints
