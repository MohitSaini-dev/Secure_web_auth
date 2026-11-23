
import base64
import hashlib
import hmac
import io
import os
import secrets
from datetime import datetime, timedelta, timezone
from utils.security_logger import log_security_event
from models.security_event import SecurityEvent
from flask_limiter.util import get_remote_address
import phonenumbers
import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import (
    VerifyMismatchError,
    VerificationError,
    InvalidHashError,
)
from cryptography.fernet import Fernet, InvalidToken
from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_mail import Message
from itsdangerous import (
    URLSafeTimedSerializer,
    BadSignature,
    SignatureExpired,
)
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException

from extensions import db, mail, limiter
from models.user import User

auth = Blueprint("auth", __name__)
password_hasher = PasswordHasher()


# ---------- General Helpers ----------

def get_logged_in_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return db.session.get(User, user_id)


def verify_password(user, password):
    try:
        return password_hasher.verify(user.password_hash, password)
    except (
        VerifyMismatchError,
        VerificationError,
        InvalidHashError,
    ):
        return False


def utcnow_naive():
    """Use consistent naive UTC timestamps for existing OTP columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------- Email Verification ----------

def generate_email_token(email):
    serializer = URLSafeTimedSerializer(
        current_app.config["SECRET_KEY"]
    )
    return serializer.dumps(
        email,
        salt=current_app.config["EMAIL_VERIFICATION_SALT"],
    )


def verify_email_token(token, max_age=86400):
    serializer = URLSafeTimedSerializer(
        current_app.config["SECRET_KEY"]
    )
    try:
        return serializer.loads(
            token,
            salt=current_app.config["EMAIL_VERIFICATION_SALT"],
            max_age=max_age,
        )
    except (BadSignature, SignatureExpired):
        return None


def send_verification_email(user):
    token = generate_email_token(user.email)
    verification_url = url_for(
        "auth.verify_email",
        token=token,
        _external=True,
    )

    message = Message(
        subject="Verify your email - Secure Auth App",
        recipients=[user.email],
        body=(
            f"Hello {user.name},\n\n"
            "Please verify your email address using this link:\n\n"
            f"{verification_url}\n\n"
            "This link expires in 24 hours.\n"
            "If you did not create this account, ignore this email."
        ),
    )
    mail.send(message)


# ---------- TOTP MFA Encryption ----------

def get_mfa_cipher():
    key = current_app.config.get("MFA_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("MFA_ENCRYPTION_KEY is missing.")

    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_totp_secret(secret):
    return get_mfa_cipher().encrypt(secret.encode()).decode()


def decrypt_totp_secret(encrypted_secret):
    if not encrypted_secret:
        return None
    try:
        return get_mfa_cipher().decrypt(
            encrypted_secret.encode()
        ).decode()
    except InvalidToken:
        current_app.logger.exception(
            "Unable to decrypt stored TOTP secret."
        )
        return None


# ---------- Home ----------

@auth.route("/")
def home():
    if session.get("user_id"):
        return redirect(url_for("auth.dashboard"))
    return render_template("home.html")


# ---------- Registration ----------

@auth.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("All fields are required.", "error")
            return render_template("register.html"), 400

        if len(password) < 12:
            flash("Password must be at least 12 characters.", "error")
            return render_template("register.html"), 400

        if User.query.filter_by(email=email).first():
            flash("An account with this email already exists.", "error")
            return render_template("register.html"), 400

        user = User(
            name=name,
            email=email,
            password_hash=password_hasher.hash(password),
            email_verified=False,
        )

        try:
            db.session.add(user)
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Registration failed.")
            flash("Registration could not be completed.", "error")
            return render_template("register.html"), 500

        try:
            send_verification_email(user)
        except Exception:
            current_app.logger.exception(
                "Verification email sending failed."
            )
            flash(
                "Your account was created, but the verification email "
                "could not be sent. Please contact support.",
                "error",
            )
            return redirect(url_for("auth.login"))

        flash(
            "Account created. Check your email to verify your address.",
            "success",
        )
        return redirect(url_for("auth.login"))

    return render_template("register.html")


# ---------- Verify Email ----------

@auth.route("/verify-email/<token>")
def verify_email(token):
    email = verify_email_token(token)
    if email is None:
        flash("The verification link is invalid or expired.", "error")
        return redirect(url_for("auth.login"))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Account not found.", "error")
        return redirect(url_for("auth.login"))

    if user.email_verified:
        flash("Your email is already verified.", "info")
        return redirect(url_for("auth.login"))

    try:
        user.email_verified = True
        db.session.commit()
        flash("Your email has been verified successfully.", "success")
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Email verification update failed.")
        flash("An error occurred while verifying your email.", "error")

    return redirect(url_for("auth.login"))



# ---------- Login ----------

@auth.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per 10 minutes", methods=["POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        # Log failed login attempts
        if not user or not verify_password(user, password):
            log_security_event(
                "login",
                success=False,
                user_id=user.id if user else None,
            )
            flash("Invalid email or password.", "error")
            return render_template("login.html"), 401

        # Require email verification
        if not user.email_verified:
            log_security_event(
                "login",
                success=False,
                user_id=user.id,
            )
            flash("Verify your email before logging in.", "error")
            return render_template("login.html"), 401

        # Clear previous session data after successful authentication
        session.clear()

        # Redirect users with MFA enabled to MFA verification
        if user.mfa_enabled:
            session["pending_mfa_user_id"] = user.id
            return redirect(url_for("auth.mfa_login"))

        # Complete login for users without MFA
        session.permanent = True
        session["user_id"] = user.id

        log_security_event(
            "login",
            success=True,
            user_id=user.id,
        )

        return redirect(url_for("auth.dashboard"))

    return render_template("login.html")

# ---------- Dashboard ----------

@auth.route("/dashboard")
def dashboard():
    user = get_logged_in_user()

    if not user:
        session.clear()
        flash("Please log in first.", "error")
        return redirect(url_for("auth.login"))

    if not user.email_verified:
        session.clear()
        flash("Please verify your email first.", "error")
        return redirect(url_for("auth.login"))

    return render_template("dashboard.html", user=user)


# ---------- TOTP MFA Login ----------

@auth.route("/mfa/login", methods=["GET", "POST"])
@limiter.limit("10 per 10 minutes", methods=["POST"])
def mfa_login():
    pending_user_id = session.get("pending_mfa_user_id")

    if pending_user_id is None:
        return redirect(url_for("auth.login"))

    user = db.session.get(User, pending_user_id)

    if (
        not user
        or not user.mfa_enabled
        or not user.totp_secret
        or not user.email_verified
    ):
        session.clear()
        flash("Please log in again.", "error")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        secret = decrypt_totp_secret(user.totp_secret)

        if (
            secret
            and code.isdigit()
            and len(code) == 6
            and pyotp.TOTP(secret).verify(code, valid_window=1)
        ):
            session.clear()
            session.permanent = True
            session["user_id"] = user.id

            log_security_event(
                "login",
                success=True,
                user_id=user.id,
            )

            return redirect(url_for("auth.dashboard"))

        log_security_event(
            "mfa_login",
            success=False,
            user_id=user.id,
        )
        flash("Invalid verification code.", "error")

    return render_template("mfa_login.html")

# ---------- MFA Setup ----------

@auth.route("/mfa/setup", methods=["GET", "POST"])
def mfa_setup():
    user = get_logged_in_user()
    if not user:
        flash("Please log in first.", "error")
        return redirect(url_for("auth.login"))

    if user.mfa_enabled:
        flash("Two-factor authentication is already enabled.", "info")
        return redirect(url_for("auth.dashboard"))

    if not user.totp_secret:
        user.totp_secret = encrypt_totp_secret(pyotp.random_base32())
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Could not save MFA secret.")
            flash("MFA setup could not be started.", "error")
            return redirect(url_for("auth.dashboard"))

    secret = decrypt_totp_secret(user.totp_secret)
    if not secret:
        flash("Could not read the MFA secret. Contact support.", "error")
        return redirect(url_for("auth.dashboard"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if (
            code.isdigit()
            and len(code) == 6
            and pyotp.TOTP(secret).verify(code, valid_window=1)
        ):
            try:
                user.mfa_enabled = True
                db.session.commit()
                flash("Two-factor authentication enabled.", "success")
                return redirect(url_for("auth.dashboard"))
            except Exception:
                db.session.rollback()
                current_app.logger.exception("Failed to enable MFA.")
                flash("Could not enable MFA. Please try again.", "error")
        else:
            flash("Enter a valid six-digit verification code.", "error")

    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
        name=user.email,
        issuer_name="Secure Auth App",
    )
    image = qrcode.make(provisioning_uri)
    image_buffer = io.BytesIO()
    image.save(image_buffer, format="PNG")
    qr_code = base64.b64encode(image_buffer.getvalue()).decode("utf-8")

    return render_template(
        "mfa_setup.html",
        qr_code=qr_code,
        secret=secret,
    )


# ---------- Disable MFA ----------

@auth.route("/mfa/disable", methods=["GET", "POST"])
@limiter.limit("10 per 10 minutes", methods=["POST"])
def mfa_disable():
    user = get_logged_in_user()
    if not user:
        flash("Please log in first.", "error")
        return redirect(url_for("auth.login"))

    if not user.mfa_enabled:
        flash("Two-factor authentication is not enabled.", "info")
        return redirect(url_for("auth.dashboard"))

    if request.method == "POST":
        password = request.form.get("password", "")
        code = request.form.get("code", "").strip()

        if not verify_password(user, password):
            flash("Incorrect password.", "error")
            return render_template("mfa_disable.html"), 401

        secret = decrypt_totp_secret(user.totp_secret)
        if (
            not secret
            or not code.isdigit()
            or len(code) != 6
            or not pyotp.TOTP(secret).verify(code, valid_window=1)
        ):
            flash("Invalid verification code.", "error")
            return render_template("mfa_disable.html"), 400

        try:
            user.mfa_enabled = False
            user.totp_secret = None
            db.session.commit()
            flash("Two-factor authentication has been disabled.", "success")
            return redirect(url_for("auth.dashboard"))
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Failed to disable MFA.")
            flash("Could not disable MFA. Please try again.", "error")

    return render_template("mfa_disable.html")


# ---------- Change Password ----------

@auth.route("/change-password", methods=["GET", "POST"])
@limiter.limit("5 per 10 minutes", methods=["POST"])
def change_password():
    user = get_logged_in_user()
    if not user:
        flash("Please log in first.", "error")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not verify_password(user, current_password):
            flash("Your current password is incorrect.", "error")
            return render_template("change_password.html"), 400

        if len(new_password) < 12:
            flash("New password must be at least 12 characters.", "error")
            return render_template("change_password.html"), 400

        if new_password != confirm_password:
            flash("New passwords do not match.", "error")
            return render_template("change_password.html"), 400

        if verify_password(user, new_password):
            flash("New password must differ from the current password.", "error")
            return render_template("change_password.html"), 400

        try:
            user.password_hash = password_hasher.hash(new_password)
            db.session.commit()
            flash("Password changed successfully.", "success")
            return redirect(url_for("auth.dashboard"))
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Password change failed.")
            flash("Could not change your password. Please try again.", "error")

    return render_template("change_password.html")


# ---------- Logout ----------

@auth.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))


# ---------- Phone Verification Helpers ----------

def phone_otp_digest(user_id, phone_number, code):
    payload = f"{user_id}:{phone_number}:{code}".encode()
    key = current_app.config["SECRET_KEY"].encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def normalize_phone_number(raw_number):
    try:
        parsed = phonenumbers.parse(raw_number, None)
        if not phonenumbers.is_valid_number(parsed):
            return None
        return phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.E164
        )
    except phonenumbers.NumberParseException:
        return None


def send_phone_otp_sms(phone_number, code):
    """Mock is only for local development; Twilio is optional."""
    provider = current_app.config.get("SMS_PROVIDER", "mock").lower()

    if provider == "mock":
        if not current_app.debug:
            raise RuntimeError("Mock SMS is allowed only in debug mode.")

        masked_number = "*" * max(0, len(phone_number) - 4) + phone_number[-4:]
        current_app.logger.warning(
            "MOCK SMS for %s | OTP: %s", masked_number, code
        )
        return

    if provider == "twilio":
        sid = current_app.config.get("TWILIO_ACCOUNT_SID")
        token = current_app.config.get("TWILIO_AUTH_TOKEN")
        sender = current_app.config.get("TWILIO_PHONE_NUMBER")

        if not all([sid, token, sender]):
            raise RuntimeError("Twilio SMS configuration is incomplete.")

        Client(sid, token).messages.create(
            to=phone_number,
            from_=sender,
            body=(
                f"Your SecureAuth verification code is {code}. "
                "It expires in 5 minutes. Do not share this code."
            ),
        )
        return

    raise RuntimeError("Unsupported SMS provider.")


# ---------- Request Phone Verification OTP ----------

@auth.route("/phone/verify", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def phone_verify():
    user = get_logged_in_user()
    if not user:
        flash("Please log in first.", "error")
        return redirect(url_for("auth.login"))

    if not user.email_verified:
        flash("Verify your email before verifying your mobile number.", "error")
        return redirect(url_for("auth.dashboard"))

    if user.phone_verified:
        flash("Your mobile number is already verified.", "info")
        return redirect(url_for("auth.dashboard"))

    if request.method == "POST":
        phone_number = normalize_phone_number(
            request.form.get("phone_number", "").strip()
        )
        if not phone_number:
            flash(
                "Enter a valid number with its country code, e.g. +919876543210.",
                "error",
            )
            return render_template("phone_verify.html", user=user), 400

        existing = User.query.filter(
            User.phone_number == phone_number,
            User.id != user.id,
        ).first()
        if existing:
            flash(
                "This mobile number is already associated with another account.",
                "error",
            )
            return render_template("phone_verify.html", user=user), 400

        now = utcnow_naive()

        if (
            user.phone_otp_sent_at
            and now - user.phone_otp_sent_at < timedelta(seconds=60)
        ):
            flash("Please wait 60 seconds between OTP requests.", "error")
            return render_template("phone_verify.html", user=user), 429

        if (
            not user.phone_otp_hour_started_at
            or now - user.phone_otp_hour_started_at >= timedelta(hours=1)
        ):
            user.phone_otp_hour_started_at = now
            user.phone_otp_hour_count = 0

        if user.phone_otp_hour_count >= 3:
            flash("OTP request limit reached. Try again in an hour.", "error")
            return render_template("phone_verify.html", user=user), 429

        code = f"{secrets.randbelow(1_000_000):06d}"

        # Reserve the request before attempting delivery.
        user.phone_number = phone_number
        user.phone_otp_sent_at = now
        user.phone_otp_hour_count += 1
        user.phone_otp_attempts = 0
        user.phone_otp_hash = None
        user.phone_otp_expires_at = None

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Could not reserve phone OTP request.")
            flash("Could not start phone verification. Please try again.", "error")
            return render_template("phone_verify.html", user=user), 500

        try:
            send_phone_otp_sms(phone_number, code)
        except (TwilioRestException, RuntimeError):
            current_app.logger.exception("Phone OTP delivery failed.")
            flash("SMS could not be sent. Check the provider configuration.", "error")
            return render_template("phone_verify.html", user=user), 502
        except Exception:
            current_app.logger.exception("Unexpected phone SMS delivery error.")
            flash("SMS delivery failed. Please try again later.", "error")
            return render_template("phone_verify.html", user=user), 502

        user.phone_otp_hash = phone_otp_digest(user.id, phone_number, code)
        user.phone_otp_expires_at = now + timedelta(minutes=5)

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Could not save phone OTP state.")
            flash("Could not save OTP state. Please request a new code.", "error")
            return render_template("phone_verify.html", user=user), 500

        flash("OTP ready. Enter the six-digit code from your development terminal.", "success")
        return redirect(url_for("auth.phone_verify"))

    return render_template("phone_verify.html", user=user)


# ---------- Check Phone Verification OTP ----------

@auth.route("/phone/verify-code", methods=["POST"])
@limiter.limit("10 per 10 minutes")
def phone_verify_code():
    user = get_logged_in_user()
    if not user:
        flash("Please log in first.", "error")
        return redirect(url_for("auth.login"))

    if not user.email_verified:
        flash("Verify your email before verifying your mobile number.", "error")
        return redirect(url_for("auth.dashboard"))

    if user.phone_verified:
        flash("Your mobile number is already verified.", "info")
        return redirect(url_for("auth.dashboard"))

    code = request.form.get("code", "").strip()
    now = utcnow_naive()

    if (
        not user.phone_number
        or not user.phone_otp_hash
        or not user.phone_otp_expires_at
        or user.phone_otp_expires_at <= now
    ):
        user.phone_otp_hash = None
        user.phone_otp_expires_at = None
        user.phone_otp_attempts = 0
        db.session.commit()
        flash("Your OTP has expired or is missing. Request a new one.", "error")
        return redirect(url_for("auth.phone_verify"))

    if user.phone_otp_attempts >= 5:
        user.phone_otp_hash = None
        user.phone_otp_expires_at = None
        db.session.commit()
        flash("Too many incorrect attempts. Request a new OTP.", "error")
        return redirect(url_for("auth.phone_verify"))

    user.phone_otp_attempts += 1
    expected = user.phone_otp_hash
    supplied = (
        phone_otp_digest(user.id, user.phone_number, code)
        if code.isdigit() and len(code) == 6
        else ""
    )

    if not hmac.compare_digest(expected, supplied):
        if user.phone_otp_attempts >= 5:
            user.phone_otp_hash = None
            user.phone_otp_expires_at = None
        db.session.commit()
        flash("Invalid verification code. Check the code and try again.", "error")
        return redirect(url_for("auth.phone_verify"))

    try:
        user.phone_verified = True
        user.phone_otp_hash = None
        user.phone_otp_expires_at = None
        user.phone_otp_attempts = 0
        db.session.commit()
        flash("Mobile number verified successfully.", "success")
        return redirect(url_for("auth.dashboard"))
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Phone verification update failed.")
        flash("Could not verify the mobile number. Please try again.", "error")
        return redirect(url_for("auth.phone_verify"))

# ---------- Security Activity ----------

@auth.route("/security/activity")
def security_activity():
    user = get_logged_in_user()

    if not user:
        flash("Please log in first.", "error")
        return redirect(url_for("auth.login"))

    events = (
        SecurityEvent.query
        .filter_by(user_id=user.id)
        .order_by(SecurityEvent.created_at.desc())
        .limit(50)
        .all()
    )

    return render_template(
        "security_activity.html",
        user=user,
        events=events,
    )

# ------------Forget password------------
@auth.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        user = User.query.filter_by(email=email).first()

        # Always show the same message to prevent account enumeration.
        if user:
            serializer = URLSafeTimedSerializer(
                current_app.config["SECRET_KEY"]
            )

            token = serializer.dumps(
                {
                    "user_id": user.id,
                    "password_hash": user.password_hash,
                },
                salt="password-reset",
            )

            reset_url = url_for(
                "auth.reset_password",
                token=token,
                _external=True,
            )

            try:
                message = Message(
                    subject="SecureAuth Password Reset",
                    recipients=[user.email],
                    body=(
                        "We received a request to reset your SecureAuth "
                        "password.\n\n"
                        f"Use this link to reset your password:\n{reset_url}\n\n"
                        "This link expires in 30 minutes. If you did not "
                        "request this, you can ignore this email."
                    ),
                )
                mail.send(message)

            except Exception:
                current_app.logger.exception(
                    "Failed to send password reset email."
                )

        flash(
            "If an account with that email exists, reset instructions "
            "have been sent.",
            "info",
        )
        return redirect(url_for("auth.login"))

    return render_template("forgot_password.html")


@auth.route("/reset-password/<token>", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def reset_password(token):
    serializer = URLSafeTimedSerializer(
        current_app.config["SECRET_KEY"]
    )

    try:
        data = serializer.loads(
            token,
            salt="password-reset",
            max_age=1800,
        )
    except (BadSignature, SignatureExpired):
        flash(
            "This password reset link is invalid or has expired. "
            "Please request a new one.",
            "warning",
        )
        return redirect(url_for("auth.forgot_password"))

    user = db.session.get(User, data.get("user_id"))

    # Reject tokens issued before the user's password last changed.
    if (
        user is None
        or data.get("password_hash") != user.password_hash
    ):
        flash(
            "This password reset link is invalid or has expired. "
            "Please request a new one.",
            "warning",
        )
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(new_password) < 12:
            flash(
                "Your password must be at least 12 characters long.",
                "danger",
            )
            return render_template("reset_password.html")

        if new_password != confirm_password:
            flash("The passwords do not match.", "danger")
            return render_template("reset_password.html")

        try:
            user.password_hash = password_hasher.hash(new_password)
            db.session.commit()

        except Exception:
            db.session.rollback()
            current_app.logger.exception(
                "Failed to reset user password."
            )
            flash(
                "Unable to reset your password right now. Please try again.",
                "danger",
            )
            return render_template("reset_password.html"), 500

        log_security_event(
            event_type="password_reset",
            user_id=user.id,
            success=True,
        )

        flash(
            "Your password has been reset. Please log in with your new password.",
            "success",
        )
        return redirect(url_for("auth.login"))

    return render_template("reset_password.html")
