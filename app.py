
from datetime import datetime, timedelta, timezone
from models.security_event import SecurityEvent

from flask import Flask, session, redirect, url_for, flash
from flask_wtf.csrf import CSRFProtect

from config import Config
from extensions import db, migrate, mail, limiter
from routes.auth import auth

csrf = CSRFProtect()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Set the session lifetime to 30 minutes
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

    # Initialize extensions
    limiter.init_app(app)
    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    csrf.init_app(app)

    # Check inactivity before each request
    @app.before_request
    def enforce_inactivity_timeout():
        if "user_id" not in session:
            return

        now = datetime.now(timezone.utc).timestamp()
        last_activity = session.get("last_activity")

        if (
            last_activity is not None
            and now - last_activity > 1800 
        ):
            session.clear()
            flash("You were logged out due to inactivity.", "info")
            return redirect(url_for("auth.login"))

        session["last_activity"] = now
        session.permanent = True

    # Register authentication routes
    app.register_blueprint(auth)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
