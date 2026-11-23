
from datetime import datetime, timezone

from extensions import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(
        db.String(100),
        nullable=False
    )

    email = db.Column(
        db.String(255),
        unique=True,
        nullable=False,
        index=True
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        nullable=False,
        default="user"
    )

    mfa_enabled = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    # Encrypted TOTP secret for MFA
    totp_secret = db.Column(
        db.String(500),
        nullable=True
    )

    # Email verification
    email_verified = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    # Mobile number and verification
    phone_number = db.Column(
        db.String(20),
        unique=True,
        nullable=True
    )

    phone_verified = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    # Mobile OTP security and rate limiting
    phone_otp_hash = db.Column(
        db.String(64),
        nullable=True
    )

    phone_otp_expires_at = db.Column(
        db.DateTime,
        nullable=True
    )

    phone_otp_attempts = db.Column(
        db.Integer,
        nullable=False,
        default=0,
        server_default="0"
    )

    phone_otp_sent_at = db.Column(
        db.DateTime,
        nullable=True
    )

    phone_otp_hour_started_at = db.Column(
        db.DateTime,
        nullable=True
    )

    phone_otp_hour_count = db.Column(
        db.Integer,
        nullable=False,
        default=0,
        server_default="0"
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )
