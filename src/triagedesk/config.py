"""Runtime settings, read from environment variables.

A local ``.env`` file is loaded if present, so secrets never need to be written into the code.
On a hosting platform, set the same variables in the platform's environment settings.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

ENRICHMENT_MODES = ("mock", "abuseipdb", "off")


@dataclass(frozen=True)
class Settings:
    enrichment_mode: str = "mock"
    abuseipdb_api_key: str | None = None
    llm_base_url: str | None = None
    llm_api_key: str | None = None
    llm_model: str | None = None
    llm_timeout_seconds: int = 30
    max_upload_mb: int = 10
    max_lines_per_file: int = 200_000
    log_timezone: str = "UTC"

    @property
    def llm_enabled(self) -> bool:
        return bool(self.llm_base_url and self.llm_api_key and self.llm_model)


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a whole number, got {value!r}") from exc


def load_settings() -> Settings:
    """Build settings from the environment. Invalid values raise ``ValueError``."""
    load_dotenv()
    mode = os.getenv("TRIAGEDESK_ENRICHMENT_MODE", "mock").strip().lower()
    if mode not in ENRICHMENT_MODES:
        raise ValueError(
            f"TRIAGEDESK_ENRICHMENT_MODE must be one of {', '.join(ENRICHMENT_MODES)}, got {mode!r}"
        )
    return Settings(
        enrichment_mode=mode,
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY") or None,
        llm_base_url=(os.getenv("LLM_BASE_URL") or "").rstrip("/") or None,
        llm_api_key=os.getenv("LLM_API_KEY") or None,
        llm_model=os.getenv("LLM_MODEL") or None,
        llm_timeout_seconds=_int_env("LLM_TIMEOUT_SECONDS", 30),
        max_upload_mb=_int_env("TRIAGEDESK_MAX_UPLOAD_MB", 10),
        max_lines_per_file=_int_env("TRIAGEDESK_MAX_LINES_PER_FILE", 200_000),
        log_timezone=os.getenv("TRIAGEDESK_LOG_TIMEZONE", "UTC"),
    )
