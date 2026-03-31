import re
from collections.abc import Iterable

COMMON_PASSWORD_PARTS = {
    "password",
    "admin",
    "welcome",
    "qwerty",
    "letmein",
    "changeme",
    "default",
    "secret",
    "test",
    "demo",
    "root",
    "user",
    "login",
    "access",
    "server",
    "123456",
    "12345678",
    "password123",
}
SEQUENTIAL_PATTERNS = (
    "0123456789",
    "1234567890",
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)


def _normalized_related_values(related_values: Iterable[str] | None):
    cleaned = []
    for value in related_values or []:
        token = re.sub(r"[^a-z0-9]", "", str(value or "").lower())
        if len(token) >= 3:
            cleaned.append(token)
    return cleaned


def evaluate_password_strength(password: str, related_values: Iterable[str] | None = None):
    password = password or ""
    if not password:
        return {
            "present": False,
            "score": 0,
            "max_score": 6,
            "level": "not_available",
            "label": "Not available",
            "checks": {
                "length": False,
                "long_length": False,
                "has_lower": False,
                "has_upper": False,
                "has_digit": False,
                "has_symbol": False,
                "has_common_pattern": False,
                "has_repetition": False,
                "has_sequence": False,
                "matches_context": False,
            },
            "suggestions": ["Add a password before running credential-strength checks."],
            "summary": "No password was supplied.",
        }

    lowered = password.lower()
    compact = re.sub(r"[^a-z0-9]", "", lowered)
    related_tokens = _normalized_related_values(related_values)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", password))
    has_common_pattern = any(part in lowered for part in COMMON_PASSWORD_PARTS)
    has_repetition = bool(re.search(r"(.){2,}", password))
    has_sequence = any(pattern in compact for pattern in SEQUENTIAL_PATTERNS)
    matches_context = any(token in compact for token in related_tokens)

    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    if variety >= 2:
        score += 1
    if variety >= 3:
        score += 1
    if variety == 4:
        score += 1
    if len(password) >= 16 and not (has_common_pattern or has_repetition or has_sequence or matches_context):
        score += 1

    penalties = sum([has_common_pattern, has_repetition, has_sequence, matches_context])
    score = max(0, min(6, score - penalties))

    if score <= 1:
        level = "weak"
        label = "Weak"
    elif score <= 3:
        level = "fair"
        label = "Fair"
    elif score <= 4:
        level = "good"
        label = "Good"
    else:
        level = "strong"
        label = "Strong"

    suggestions = []
    if len(password) < 12:
        suggestions.append("Use at least 12 characters; 14 to 16 is safer for admin or server access.")
    if not has_upper:
        suggestions.append("Add at least one uppercase letter.")
    if not has_lower:
        suggestions.append("Add at least one lowercase letter.")
    if not has_digit:
        suggestions.append("Add at least one number.")
    if not has_symbol:
        suggestions.append("Add at least one special character such as !, @, or #.")
    if has_common_pattern:
        suggestions.append("Avoid common words like password, admin, welcome, or test.")
    if has_repetition:
        suggestions.append("Avoid repeated characters such as aaa or 111.")
    if has_sequence:
        suggestions.append("Avoid simple keyboard or numeric sequences such as 123456 or qwerty.")
    if matches_context:
        suggestions.append("Do not include the project name, domain, email name, or server name in the password.")
    if not suggestions:
        suggestions.append("Password looks strong. Keep it unique and rotate it if it has been shared before.")

    summary = {
        "weak": "Password is easy to guess and should be changed before relying on it.",
        "fair": "Password is usable for testing but should be strengthened for better protection.",
        "good": "Password is reasonably strong, though a longer unique passphrase would be better.",
        "strong": "Password is strong and follows recommended complexity rules.",
    }.get(level, "Password strength could not be determined.")

    return {
        "present": True,
        "score": score,
        "max_score": 6,
        "level": level,
        "label": label,
        "checks": {
            "length": len(password) >= 8,
            "long_length": len(password) >= 12,
            "has_lower": has_lower,
            "has_upper": has_upper,
            "has_digit": has_digit,
            "has_symbol": has_symbol,
            "has_common_pattern": has_common_pattern,
            "has_repetition": has_repetition,
            "has_sequence": has_sequence,
            "matches_context": matches_context,
        },
        "suggestions": suggestions,
        "summary": summary,
    }
