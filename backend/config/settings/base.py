import importlib.util
from datetime import timedelta
from pathlib import Path

from celery.schedules import crontab

from .helpers import env, env_bool, env_int, env_list, load_env_file

BASE_DIR = Path(__file__).resolve().parents[2]
load_env_file(BASE_DIR / ".env")

SECRET_KEY = env("DJANGO_SECRET_KEY", "replace-me-for-local-dev")
DEBUG = env_bool("DJANGO_DEBUG", True)
ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", ["127.0.0.1", "localhost"])

DJANGO_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

THIRD_PARTY_APPS = [
    "corsheaders",
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    "django_celery_results",
]

OPTIONAL_APPS = []
if importlib.util.find_spec("django_celery_beat"):
    OPTIONAL_APPS.append("django_celery_beat")

LOCAL_APPS = [
    "apps.common",
    "apps.accounts",
    "apps.projects",
    "apps.scans",
    "apps.reports",
    "apps.notifications",
    "apps.analytics",
    "apps.ai_core",
    "apps.surface_scan",
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + OPTIONAL_APPS + LOCAL_APPS

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": env("MYSQL_DATABASE"),
        "USER": env("MYSQL_USER"),
        "PASSWORD": env("MYSQL_PASSWORD"),
        "HOST": env("MYSQL_HOST"),
        "PORT": env("MYSQL_PORT"),
        "CONN_MAX_AGE": env_int("MYSQL_CONN_MAX_AGE", 60),
        "OPTIONS": {
            "charset": "utf8mb4",
            "init_command": "SET sql_mode='STRICT_TRANS_TABLES'",
        },
    }
}

AUTH_USER_MODEL = "accounts.User"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = env("DJANGO_TIME_ZONE", "Asia/Kolkata")
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
FIELD_ENCRYPTION_KEY = env("FIELD_ENCRYPTION_KEY", "")

CORS_ALLOWED_ORIGINS = env_list(
    "CORS_ALLOWED_ORIGINS",
    ["http://localhost:5173", "http://127.0.0.1:5173"],
)
CSRF_TRUSTED_ORIGINS = env_list("CSRF_TRUSTED_ORIGINS", CORS_ALLOWED_ORIGINS)
CORS_ALLOW_CREDENTIALS = True
CORS_EXPOSE_HEADERS = ["Content-Disposition"]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": env_int("API_PAGE_SIZE", 20),
    "DEFAULT_FILTER_BACKENDS": (
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ),
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=env_int("JWT_ACCESS_MINUTES", 30)),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=env_int("JWT_REFRESH_DAYS", 7)),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
    "AUTH_HEADER_TYPES": ("Bearer",),
}

REDIS_URL = env("REDIS_URL", "redis://127.0.0.1:6379/0")
CELERY_BROKER_URL = env("CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND = env("CELERY_RESULT_BACKEND", "django-db")
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = TIME_ZONE
CELERY_TASK_TIME_LIMIT = env_int("CELERY_TASK_TIME_LIMIT", 300)
CELERY_TASK_SOFT_TIME_LIMIT = env_int("CELERY_TASK_SOFT_TIME_LIMIT", 240)
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
CELERY_BEAT_SCHEDULER = (
    "django_celery_beat.schedulers:DatabaseScheduler"
    if "django_celery_beat" in INSTALLED_APPS
    else "celery.beat:PersistentScheduler"
)
CELERY_BEAT_SCHEDULE = {
    "dispatch-due-scans": {
        "task": "apps.scans.tasks.dispatch_due_project_scans",
        "schedule": crontab(minute="*/15"),
    }
}

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = env("SMTP_HOST", "127.0.0.1")
EMAIL_PORT = env_int("SMTP_PORT", 587)
EMAIL_HOST_USER = env("SMTP_USER", "")
EMAIL_HOST_PASSWORD = env("SMTP_PASSWORD", "")
EMAIL_USE_TLS = env_bool("SMTP_USE_TLS", True)
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", "AEGIS AI <no-reply@localhost>")

FRONTEND_URL = env("FRONTEND_URL", "http://localhost:5173")
OPENROUTER_BASE_URL = env("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
OPENROUTER_API_KEY = env("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = env("OPENROUTER_MODEL", "")
OPENROUTER_SITE_URL = env("OPENROUTER_SITE_URL", FRONTEND_URL)
OPENROUTER_APP_NAME = env("OPENROUTER_APP_NAME", "AEGIS AI")
OLLAMA_BASE_URL = env("OLLAMA_BASE_URL", "http://localhost:11434/api")
OLLAMA_MODEL = env("OLLAMA_MODEL", "qwen2.5:3b")
SURFACE_SCAN_USER_AGENT = env("SURFACE_SCAN_USER_AGENT", "AEGIS AI Surface Scanner/1.0 (+local)")
SURFACE_SCAN_CONNECT_TIMEOUT = env_int("SURFACE_SCAN_CONNECT_TIMEOUT", 4)
SURFACE_SCAN_READ_TIMEOUT = env_int("SURFACE_SCAN_READ_TIMEOUT", 6)
SURFACE_SCAN_CT_ENABLED = env_bool("SURFACE_SCAN_CT_ENABLED", True)
CRTSH_BASE_URL = env("CRTSH_BASE_URL", "https://crt.sh/")
SSL_LABS_ENABLED = env_bool("SSL_LABS_ENABLED", False)
SSL_LABS_API_URL = env("SSL_LABS_API_URL", "https://api.ssllabs.com/api/v3/analyze")
GITHUB_TOKEN = env("GITHUB_TOKEN", "")
GITHUB_PUSH_BRANCH = env("GITHUB_PUSH_BRANCH", "main")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "[{asctime}] {levelname} {name}: {message}",
            "style": "{",
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": BASE_DIR / "logs" / "app.log",
            "formatter": "standard",
        },
    },
    "loggers": {
        "": {
            "handlers": ["console", "file"],
            "level": "INFO",
        },
    },
}




