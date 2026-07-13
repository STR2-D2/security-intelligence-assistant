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

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @field_validator("nvd_api_key", mode="before")
    @classmethod
    def empty_nvd_api_key_to_none(cls, value: str | None) -> str | None:
        if isinstance(value, str) and not value.strip():
            return None
        return value


settings = Settings()
