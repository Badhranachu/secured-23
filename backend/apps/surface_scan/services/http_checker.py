from urllib.parse import urlparse

import requests
from django.conf import settings

from apps.common.utils.targets import build_candidate_urls_for_target, default_api_base_url_for_target, parse_target_parts
from apps.surface_scan.services.result_utils import clean_text, hostname_from_url, status_payload
from apps.surface_scan.services.timing_utils import elapsed_ms, timer_start

REQUEST_HEADERS = {
    "User-Agent": getattr(settings, "SURFACE_SCAN_USER_AGENT", "AEGIS AI Surface Scanner/1.0"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.7",
    "Cache-Control": "no-cache",
}
MAX_REDIRECTS = 6



def _build_redirect_chain(response):
    history = list(response.history or [])
    if not history:
        return []
    chain = []
    for index, item in enumerate(history):
        next_url = response.url if index == len(history) - 1 else history[index + 1].url
        chain.append(
            {
                "from": clean_text(item.url),
                "to": clean_text(item.headers.get("location") or next_url),
                "status_code": item.status_code,
                "location_header": clean_text(item.headers.get("location")),
            }
        )
    return chain



def _request_url(url):
    timeout = (
        getattr(settings, "SURFACE_SCAN_CONNECT_TIMEOUT", 4),
        getattr(settings, "SURFACE_SCAN_READ_TIMEOUT", 6),
    )
    started = timer_start()
    try:
        response = requests.get(url, headers=REQUEST_HEADERS, timeout=timeout, allow_redirects=True)
        content_type = clean_text(response.headers.get("content-type"))
        content_length = response.headers.get("content-length")
        body_text = response.text[:12000] if "text" in content_type.lower() or "json" in content_type.lower() or "xml" in content_type.lower() else ""
        latency_ms = elapsed_ms(started)
        return status_payload(
            "success",
            reachable=True,
            url=url,
            status_code=response.status_code,
            final_url=clean_text(response.url),
            latency_ms=latency_ms,
            ttfb_ms=round(response.elapsed.total_seconds() * 1000, 2),
            redirect_chain=_build_redirect_chain(response),
            redirect_count=len(response.history or []),
            headers={key: clean_text(value) for key, value in response.headers.items()},
            content_type=content_type,
            content_length=int(content_length) if str(content_length).isdigit() else len(response.content or b""),
            text_excerpt=body_text,
            error_message="",
        )
    except requests.TooManyRedirects as exc:
        return status_payload(
            "check_failed",
            reachable=False,
            url=url,
            status_code=None,
            final_url="",
            latency_ms=elapsed_ms(started),
            ttfb_ms=None,
            redirect_chain=[],
            redirect_count=MAX_REDIRECTS,
            headers={},
            content_type="",
            content_length=None,
            text_excerpt="",
            error_message=f"Too many redirects: {clean_text(exc)}",
        )
    except Exception as exc:
        return status_payload(
            "check_failed",
            reachable=False,
            url=url,
            status_code=None,
            final_url="",
            latency_ms=elapsed_ms(started),
            ttfb_ms=None,
            redirect_chain=[],
            redirect_count=0,
            headers={},
            content_type="",
            content_length=None,
            text_excerpt="",
            error_message=clean_text(exc),
        )



def _analyze_redirects(target, preferred_response):
    parts = parse_target_parts(target)
    expected_host = parts["host"]
    start_url = clean_text(preferred_response.get("url"))
    final_url = clean_text(preferred_response.get("final_url"))
    chain = preferred_response.get("redirect_chain", []) or []
    final_host = hostname_from_url(final_url)
    start_host = hostname_from_url(start_url)
    parsed_final = urlparse(final_url) if final_url else None
    https_enforced = bool(final_url and parsed_final.scheme == "https")
    canonical_host = final_host or expected_host
    host_mismatch = bool(final_host and final_host != expected_host and not final_host.endswith(f".{expected_host}") and not expected_host.endswith(f".{final_host}"))
    loop_detected = len({step.get("from") for step in chain}) != len(chain)

    if start_host.startswith("www.") and final_host == start_host[4:]:
        www_policy = "redirects_to_apex"
    elif not start_host.startswith("www.") and final_host.startswith("www."):
        www_policy = "redirects_to_www"
    elif final_host == start_host:
        www_policy = "keeps_host"
    else:
        www_policy = "mixed_or_unknown"

    downgrade_detected = any(
        str(step.get("from", "")).startswith("https://") and str(step.get("to", "")).startswith("http://")
        for step in chain
    )
    redirect_mismatch_warning = host_mismatch or downgrade_detected or loop_detected

    return {
        "start_url": start_url,
        "redirect_chain": chain,
        "final_url": final_url,
        "redirect_count": preferred_response.get("redirect_count", len(chain)),
        "final_canonical_host": canonical_host,
        "https_enforced": https_enforced,
        "www_policy": www_policy,
        "loop_detected": loop_detected,
        "redirect_mismatch_warning": redirect_mismatch_warning,
        "downgrade_detected": downgrade_detected,
        "host_mismatch": host_mismatch,
        "redirect_resolution_time_ms": preferred_response.get("latency_ms"),
    }



def check_http_reachability(target: str):
    candidate_urls = build_candidate_urls_for_target(target)
    primary_url = candidate_urls[0]
    secondary_url = candidate_urls[1] if len(candidate_urls) > 1 else None
    primary_result = _request_url(primary_url)
    secondary_result = _request_url(secondary_url) if secondary_url else status_payload("not_available", reachable=False, url="", status_code=None, final_url="", latency_ms=None, ttfb_ms=None, redirect_chain=[], redirect_count=0, headers={}, content_type="", content_length=None, text_excerpt="", error_message="")

    http_result = primary_result if primary_url.startswith("http://") else secondary_result
    https_result = primary_result if primary_url.startswith("https://") else secondary_result
    preferred = https_result if https_result.get("reachable") else http_result if http_result.get("reachable") else primary_result if primary_result.get("reachable") else secondary_result if secondary_result.get("reachable") else None
    final_url = preferred.get("final_url") if preferred else ""
    selected_headers = preferred.get("headers", {}) if preferred else {}
    parsed_final = urlparse(final_url) if final_url else None
    base_url = f"{parsed_final.scheme}://{parsed_final.netloc}" if parsed_final and parsed_final.netloc else default_api_base_url_for_target(target)
    redirect_analysis = _analyze_redirects(target, preferred) if preferred else {
        "start_url": "",
        "redirect_chain": [],
        "final_url": "",
        "redirect_count": 0,
        "final_canonical_host": parse_target_parts(target)["host"],
        "https_enforced": False,
        "www_policy": "unknown",
        "loop_detected": False,
        "redirect_mismatch_warning": False,
        "downgrade_detected": False,
        "host_mismatch": False,
        "redirect_resolution_time_ms": None,
    }

    return status_payload(
        "success" if preferred else "check_failed",
        target=target,
        http=http_result,
        https=https_result,
        preferred_scheme="https" if https_result.get("reachable") else "http" if http_result.get("reachable") else "none",
        final_url=final_url,
        selected_headers=selected_headers,
        selected_html=preferred.get("text_excerpt", "") if preferred else "",
        selected_content_type=preferred.get("content_type", "") if preferred else "",
        selected_content_length=preferred.get("content_length") if preferred else None,
        base_url=base_url,
        redirect_analysis=redirect_analysis,
        suspicious_redirect=redirect_analysis.get("redirect_mismatch_warning", False),
        metrics={
            "http_response_time_ms": http_result.get("latency_ms"),
            "https_response_time_ms": https_result.get("latency_ms"),
            "redirect_resolution_time_ms": redirect_analysis.get("redirect_resolution_time_ms"),
            "http_ttfb_ms": http_result.get("ttfb_ms"),
            "https_ttfb_ms": https_result.get("ttfb_ms"),
        },
    )
