from typing import Any

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


EMAIL_PROVIDER_PRESETS: dict[str, dict[str, Any]] = {
    "163": {
        "smtp_host": "smtp.163.com",
        "smtp_port": 465,
        "smtp_use_ssl": True,
        "smtp_use_tls": False,
    },
    "qq": {
        "smtp_host": "smtp.qq.com",
        "smtp_port": 465,
        "smtp_use_ssl": True,
        "smtp_use_tls": False,
    },
}


class Settings(BaseSettings):
    app_name: str = "Security Intelligence Assistant"
    environment: str = "development"
    log_level: str = "INFO"
    database_url: str = "sqlite:///./security_intelligence.db"
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str | None = None
    nvd_results_per_page: int = 2000
    nvd_request_delay_seconds: float = 6.0
    nvd_lookback_days: int = 7
    email_provider: str | None = None
    email_username: str | None = None
    email_password: str | None = None
    email_from_name: str | None = None
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_address: str | None = None
    smtp_from_name: str | None = None
    smtp_use_tls: bool | None = None
    smtp_use_ssl: bool | None = None
    smtp_timeout_seconds: float = 30.0
    report_email_recipients: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @field_validator("nvd_api_key", mode="before")
    @classmethod
    def empty_nvd_api_key_to_none(cls, value: str | None) -> str | None:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator(
        "email_provider",
        "email_username",
        "email_password",
        "email_from_name",
        "smtp_host",
        "smtp_username",
        "smtp_password",
        "smtp_from_address",
        "smtp_from_name",
        mode="before",
    )
    @classmethod
    def empty_smtp_strings_to_none(cls, value: str | None) -> str | None:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("smtp_port", "smtp_use_tls", "smtp_use_ssl", mode="before")
    @classmethod
    def empty_smtp_overrides_to_none(cls, value: Any) -> Any:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @model_validator(mode="after")
    def validate_email_provider(self) -> "Settings":
        if self.email_provider is None:
            return self

        provider = self.email_provider.strip().lower()
        if provider not in EMAIL_PROVIDER_PRESETS:
            supported = ", ".join(sorted(EMAIL_PROVIDER_PRESETS))
            raise ValueError(
                f"Unsupported EMAIL_PROVIDER: {self.email_provider!r}. "
                f"Supported providers: {supported}"
            )

        self.email_provider = provider
        return self

    def resolve_smtp_settings(self) -> dict[str, Any]:
        provider_config: dict[str, Any] = {}
        if self.email_provider:
            provider_config = EMAIL_PROVIDER_PRESETS[self.email_provider]

        smtp_host = self.smtp_host or provider_config.get("smtp_host")
        smtp_port = (
            self.smtp_port
            if self.smtp_port is not None
            else provider_config.get("smtp_port")
        )
        smtp_use_ssl = (
            self.smtp_use_ssl
            if self.smtp_use_ssl is not None
            else provider_config.get("smtp_use_ssl", False)
        )
        smtp_use_tls = (
            self.smtp_use_tls
            if self.smtp_use_tls is not None
            else provider_config.get("smtp_use_tls", False)
        )
        smtp_username = self.smtp_username or self.email_username
        smtp_password = self.smtp_password or self.email_password
        smtp_from_address = self.smtp_from_address or smtp_username
        smtp_from_name = (
            self.smtp_from_name
            or self.email_from_name
            or "Security Intelligence Assistant"
        )

        if not smtp_host:
            raise ValueError("SMTP host is not configured. Set EMAIL_PROVIDER or SMTP_HOST.")
        if smtp_port is None:
            raise ValueError("SMTP port is not configured. Set EMAIL_PROVIDER or SMTP_PORT.")
        if smtp_use_ssl and smtp_use_tls:
            raise ValueError("SMTP_USE_SSL and SMTP_USE_TLS cannot both be enabled.")
        if not smtp_username:
            raise ValueError(
                "Email username is not configured. Set EMAIL_USERNAME or SMTP_USERNAME."
            )
        if not smtp_password:
            raise ValueError(
                "Email password is not configured. Set EMAIL_PASSWORD or SMTP_PASSWORD."
            )

        return {
            "smtp_host": smtp_host,
            "smtp_port": smtp_port,
            "smtp_username": smtp_username,
            "smtp_password": smtp_password,
            "smtp_from_address": smtp_from_address,
            "smtp_from_name": smtp_from_name,
            "smtp_use_tls": smtp_use_tls,
            "smtp_use_ssl": smtp_use_ssl,
            "smtp_timeout_seconds": self.smtp_timeout_seconds,
        }


settings = Settings()
