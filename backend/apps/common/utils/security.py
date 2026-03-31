import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


def _build_fernet() -> Fernet:
    configured_key = getattr(settings, "FIELD_ENCRYPTION_KEY", "") or ""
    if configured_key:
        return Fernet(configured_key.encode())

    derived_key = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(derived_key))


def encrypt_value(value: str) -> str:
    if not value:
        return ""
    return _build_fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_value(value: str) -> str:
    if not value:
        return ""
    try:
        return _build_fernet().decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return ""


def mask_secret(value: str, prefix: int = 4, suffix: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= prefix + suffix:
        return "*" * len(value)
    return f"{value[:prefix]}{'*' * (len(value) - prefix - suffix)}{value[-suffix:]}"
