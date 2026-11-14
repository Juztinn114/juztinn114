
import os
import secrets
import time
import smtplib
from email.message import EmailMessage
from functools import wraps

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)
from dotenv import load_dotenv
from werkzeug.security import (
    check_password_hash, generate_password_hash
)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")

MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")

# Temporary OTP storage (for this demonstration)
pending_otps = {}

# OTP expiration: 5 minutes
OTP_EXPIRATION = 300


def send_otp(receiver, otp):
    msg = EmailMessage()
    msg["Subject"] = "Admin Login Verification"
    msg["From"] = MAIL_USERNAME
    msg["To"] = receiver

    msg.set_content(f"""
Hello Admin,

Your verification code is:

{otp}

This OTP will expire in 5 minutes.

If you did not request this code, you can ignore this email.

Admin Security System
""")

    with smtplib.SMTP_SSL(
        "smtp.gmail.com", 465, timeout=15
    ) as server:
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.send_message(msg)


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("admin_authenticated"):
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


@app.route("/", methods=["GET", "POST"])
def login():

    if session.get("admin_authenticated"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if (
            email == ADMIN_EMAIL.lower()
            and check_password_hash(ADMIN_PASSWORD_HASH, password)
        ):

            otp = f"{secrets.randbelow(1000000):06d}"
            token = secrets.token_urlsafe(32)

            pending_otps[token] = {
                "otp_hash": generate_password_hash(otp),
                "expires": time.time() + OTP_EXPIRATION,
                "attempts": 0
            }

            try:
                send_otp(email, otp)

                session.clear()
                session["otp_token"] = token

                flash("OTP sent to your Gmail!", "success")
                return redirect(url_for("verify"))

            except Exception:
                pending_otps.pop(token, None)
                flash("Unable to send OTP. Check your Gmail settings.", "error")

        else:
            flash("Invalid admin email or password.", "error")

    return render_template("login.html")


@app.route("/verify", methods=["GET", "POST"])
def verify():

    token = session.get("otp_token")
    record = pending_otps.get(token)

    if not record:
        session.pop("otp_token", None)
        flash("Please login again.", "error")
        return redirect(url_for("login"))

    if time.time() > record["expires"]:
        pending_otps.pop(token, None)
        session.pop("otp_token", None)
        flash("OTP expired. Please login again.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":

        entered_otp = request.form.get("otp", "").strip()

        if check_password_hash(record["otp_hash"], entered_otp):

            pending_otps.pop(token, None)
            session.clear()
            session["admin_authenticated"] = True

            flash("Admin verification successful!", "success")
            return redirect(url_for("dashboard"))

        record["attempts"] += 1

        if record["attempts"] >= 5:
            pending_otps.pop(token, None)
            session.pop("otp_token", None)
            flash("Too many incorrect attempts. Login again.", "error")
            return redirect(url_for("login"))

        flash("Incorrect OTP. Please try again.", "error")

    return render_template("verify.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/logout")
def logout():
    token = session.get("otp_token")

    if token:
        pending_otps.pop(token, None)

    session.clear()
    flash("You have logged out successfully.", "success")

    return redirect(url_for("login"))


if __name__ == "__main__":

    required = [
        app.secret_key,
        ADMIN_EMAIL,
        ADMIN_PASSWORD_HASH,
        MAIL_USERNAME,
        MAIL_PASSWORD
    ]

    if not all(required):
        raise RuntimeError("Please complete your .env configuration.")

    app.run(debug=True)
