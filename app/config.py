from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_address: str | None = None
    smtp_from_name: str = "Security Intelligence Assistant"
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False
    smtp_timeout_seconds: float = 30.0
    report_email_recipients: str = ""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @field_validator("nvd_api_key", mode="before")
    @classmethod
    def empty_nvd_api_key_to_none(cls, value: str | None) -> str | None:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator(
        "smtp_host",
        "smtp_username",
        "smtp_password",
        "smtp_from_address",
        mode="before",
    )
    @classmethod
    def empty_smtp_strings_to_none(cls, value: str | None) -> str | None:
        if isinstance(value, str) and not value.strip():
            return None
        return value


settings = Settings()
