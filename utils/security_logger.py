
from flask import request, current_app
from extensions import db
from models.security_event import SecurityEvent


def log_security_event(
    event_type,
    success=True,
    user_id=None,
):
    try:
        event = SecurityEvent(
            user_id=user_id,
            event_type=event_type,
            success=success,
            ip_address=request.remote_addr,
        )
        db.session.add(event)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception(
            "Failed to record security event: %s",
            event_type,
        )

