import pytest
from pydantic import ValidationError

from app.config import Settings


def test_163_email_provider_preset() -> None:
    settings = Settings(
        _env_file=None,
        email_provider="163",
        email_username="sender@163.com",
        email_password="authorization-code",
        email_from_name="Security Intelligence Assistant",
    )

    resolved = settings.resolve_smtp_settings()

    assert resolved["smtp_host"] == "smtp.163.com"
    assert resolved["smtp_port"] == 465
    assert resolved["smtp_use_ssl"] is True
    assert resolved["smtp_use_tls"] is False
    assert resolved["smtp_username"] == "sender@163.com"
    assert resolved["smtp_password"] == "authorization-code"
    assert resolved["smtp_from_address"] == "sender@163.com"
    assert resolved["smtp_from_name"] == "Security Intelligence Assistant"


def test_qq_email_provider_preset() -> None:
    settings = Settings(
        _env_file=None,
        email_provider="qq",
        email_username="sender@qq.com",
        email_password="authorization-code",
    )

    resolved = settings.resolve_smtp_settings()

    assert resolved["smtp_host"] == "smtp.qq.com"
    assert resolved["smtp_port"] == 465
    assert resolved["smtp_use_ssl"] is True
    assert resolved["smtp_use_tls"] is False


def test_unknown_email_provider_is_rejected() -> None:
    with pytest.raises(ValidationError, match="Unsupported EMAIL_PROVIDER"):
        Settings(
            _env_file=None,
            email_provider="unknown-provider",
        )


def test_manual_smtp_settings_override_provider() -> None:
    settings = Settings(
        _env_file=None,
        email_provider="163",
        email_username="sender@163.com",
        email_password="authorization-code",
        smtp_host="mail.internal.example",
        smtp_port=587,
        smtp_use_ssl=False,
        smtp_use_tls=True,
    )

    resolved = settings.resolve_smtp_settings()

    assert resolved["smtp_host"] == "mail.internal.example"
    assert resolved["smtp_port"] == 587
    assert resolved["smtp_use_ssl"] is False
    assert resolved["smtp_use_tls"] is True


def test_manual_credentials_override_simple_credentials() -> None:
    settings = Settings(
        _env_file=None,
        email_provider="163",
        email_username="simple@163.com",
        email_password="simple-password",
        smtp_username="advanced@example.com",
        smtp_password="advanced-password",
    )

    resolved = settings.resolve_smtp_settings()

    assert resolved["smtp_username"] == "advanced@example.com"
    assert resolved["smtp_password"] == "advanced-password"


def test_ssl_and_tls_cannot_both_be_enabled() -> None:
    settings = Settings(
        _env_file=None,
        email_provider="163",
        email_username="sender@163.com",
        email_password="authorization-code",
        smtp_use_ssl=True,
        smtp_use_tls=True,
    )

    with pytest.raises(ValueError, match="cannot both be enabled"):
        settings.resolve_smtp_settings()
