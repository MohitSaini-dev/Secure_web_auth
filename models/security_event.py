
from datetime import datetime, timezone

from extensions import db


class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True,
        index=True,
    )

    event_type = db.Column(db.String(50), nullable=False, index=True)
    success = db.Column(db.Boolean, nullable=False, default=True)
    ip_address = db.Column(db.String(45), nullable=True)

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
