from apps.common.utils.targets import build_candidate_urls_for_target, normalize_target_value, parse_target_parts


class DomainNormalizationError(ValueError):
    pass



def normalize_domain_input(raw_value: str) -> str:
    try:
        return normalize_target_value(raw_value)
    except Exception as exc:
        raise DomainNormalizationError(str(exc)) from exc



def build_candidate_urls(hostname: str):
    return build_candidate_urls_for_target(hostname)



def extract_target_parts(raw_value: str):
    try:
        return parse_target_parts(raw_value)
    except Exception as exc:
        raise DomainNormalizationError(str(exc)) from exc
