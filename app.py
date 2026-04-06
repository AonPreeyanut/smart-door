from flask import Flask, render_template, request, redirect, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
import datetime
import secrets
import time
import os
import hashlib
import hmac
from werkzeug.security import generate_password_hash, check_password_hash
import threading
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp
from functools import wraps
from flask import session
from flask_wtf import CSRFProtect

app = Flask(__name__)

# 🔐 SECRET KEY (ปลอดภัย)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# 🔐 DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

app.permanent_session_lifetime = datetime.timedelta(minutes=5)

# 🔑 Token
API_TOKEN = secrets.token_hex(16)

# 🚪 Door Status
door_status = "LOCKED"

# 🔢 OTP
OTP_SECRET = pyotp.random_base32()
OTP_INTERVAL = 20  # วินาที

# 🚫 Rate limit (ง่ายๆ)
otp_request_time = {}

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per minute"]
)

csrf = CSRFProtect(app)
# ----------------------
# DATABASE
# ----------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    password = db.Column(db.String(200))
    role = db.Column(db.String(50))

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(100))
    action = db.Column(db.String(100))   # login / open / close / otp
    method = db.Column(db.String(50))    # web / mobile / otp
    ip = db.Column(db.String(100))       # IP Address
    device = db.Column(db.String(200))   # User-Agent
    time = db.Column(db.String(100))
    status = db.Column(db.String(50))

class Door(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(20))

class OTPAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(100))
    API_TOKEN = db.Column(db.String(100))
    timestamp = db.Column(db.Float)

# ----------------------
# HELPERS
# ----------------------
def get_client_info():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get("User-Agent", "").lower()

    # 🔍 แยกประเภทอุปกรณ์
    if "iphone" in user_agent:
        device_type = "iPhone"
    elif "android" in user_agent:
        device_type = "Android"
    elif "windows" in user_agent:
        device_type = "Windows PC"
    elif "mac" in user_agent:
        device_type = "Mac"
    else:
        device_type = "Unknown"

    # 🌐 แยก browser
    if "chrome" in user_agent:
        browser = "Chrome"
    elif "safari" in user_agent and "chrome" not in user_agent:
        browser = "Safari"
    elif "firefox" in user_agent:
        browser = "Firefox"
    else:
        browser = "Other"

    device = f"{device_type} - {browser}"

    return ip, device

# เก็บชนิดอุปกรณ์
def get_device_type():
    user_agent = request.headers.get("User-Agent", "").lower()

    if "mobile" in user_agent:
        device = "mobile"
    else:
        device = "web"
    
    session["device"] = device
    return device
    
# 🔢 OTP generate
def generate_otp():
    totp = pyotp.TOTP(OTP_SECRET)
    return totp.now()

def verify_otp(user_otp):
    totp = pyotp.TOTP(OTP_SECRET)
    return totp.verify(user_otp, valid_window=1)

# 🔐 secure compare
def secure_compare(a, b):
    return hmac.compare_digest(a, b)

def auto_lock():
    time.sleep(5)
    with app.app_context():
        door = Door.query.first()
        door.status = "LOCKED"
        db.session.commit()

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-API-KEY")

        if not token or not secure_compare(token, API_TOKEN):
            return "❌ Unauthorized", 403

        return f(*args, **kwargs)
    return decorated

def regenerate_session():
    old = dict(session)
    session.clear()
    session.update(old)

# ----------------------
# LOGIN
# ----------------------
@app.route("/", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    ip, device = get_client_info()
    method = get_device_type()

    if request.method == "POST":

        user = request.form["username"]
        pw = request.form["password"]

        found = User.query.filter_by(username=user).first()

        if found and check_password_hash(found.password, pw):
            regenerate_session()
            session["user"] = user
            session["role"] = found.role
            session.permanent = True

            log = Log(
                user=user, 
                action="login : Login Successful", 
                method=method,
                ip=ip, 
                device=device,
                time=str(datetime.datetime.now()), 
                status="success"
                )
            db.session.add(log)
            db.session.commit()

            session["user"] = user 

            return redirect("/dashboard")

        else:

            log = Log(
                user=user, 
                action="login : Login Failed", 
                method=method,
                ip=ip, 
                device=device,
                time=str(datetime.datetime.now()), 
                status="fail"
            )
            db.session.add(log)
            db.session.commit()

            flash("❌ Login Failed", "danger")

    return render_template("login.html")

# ----------------------
# DASHBOARD
# ----------------------
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    
    door = Door.query.first()
    if not door:
        door = Door(status="LOCKED")
        db.session.add(door)
        db.session.commit()

    return render_template(
        "dashboard.html",
        role=session.get("role"),
        door_status=door.status,
        token=API_TOKEN
    )

# ----------------------
# 🚪 OPEN DOOR
# ----------------------
@app.route("/open-door")
@require_token
def open_door():
    global door_status
    ip, device = get_client_info()
    token = request.headers.get("X-API-KEY")
    source = request.args.get("source") or get_device_type()

    if "user" not in session:
        return redirect("/")

    if not session.get("otp_verified"):

        log = Log(
            user=session["user"],
            action="open door : OTP Not Verified",
            method=source,
            ip=ip,
            device=device,
            time=str(datetime.datetime.now()),
            status="fail"
        )
        db.session.add(log)
        db.session.commit()

        flash("❌ Please verify OTP first", "danger")
        return redirect("/otp")

    if not secure_compare(token, API_TOKEN):

        log = Log(
            user=session["user"],
            action="open door : Invalid Token",
            method=source,
            ip=ip,
            device=device,
            time=str(datetime.datetime.now()),
            status="fail"
        )
        db.session.add(log)
        db.session.commit()

        flash("❌ Invalid token", "danger")
        return redirect("/dashboard")

    door = Door.query.first()
    if not door:
        door = Door(status="LOCKED")
        db.session.add(door)

    door.status = "UNLOCKED"
    db.session.commit()

    # 🔄 reset OTP หลังใช้
    session["otp_verified"] = False

    log = Log(
        user=session["user"],
        action="open door : Successful",
        method=source,
        ip=ip,
        device=device,
        time=str(datetime.datetime.now()),
        status="success"
    )
    db.session.add(log)
    db.session.commit()

    threading.Thread(target=auto_lock, daemon=True).start()
    flash("🚪 Door Opened", "success")
    return redirect("/dashboard")

# ----------------------
# 🔒 CLOSE DOOR
# ----------------------
@app.route("/close-door")
def close_door():
    if "user" not in session:
        return redirect("/")

    door = Door.query.first()
    if not door:
        door = Door(status="LOCKED")
        db.session.add(door)


    door.status = "LOCKED"
    db.session.commit()

    source = get_device_type()

    ip, device = get_client_info()

    log = Log(
        user=session["user"],
        action="close door : Successful",
        method=source,
        ip=ip,
        device=device,
        time=str(datetime.datetime.now()),
        status="success"
    )
    db.session.add(log)
    db.session.commit()

    flash("🔒 Door Locked", "info")
    return redirect("/dashboard")

# ----------------------
# 📱 REQUEST OTP (Mobile)
# ----------------------
@app.route("/request-otp", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def request_otp():
    if get_device_type() != "mobile":
        return "❌ Mobile Only"
    
    ip, _ = get_client_info()
    now = time.time()

    otp_request_time[ip] = now

    otp = generate_otp()
    return render_template("request_otp.html", otp=otp)

# ----------------------
# 🔢 ENTER OTP (Web)
# ----------------------
@app.route("/otp", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def otp():
    if "user" not in session:
        return redirect("/")

    if "mobile" in request.headers.get("User-Agent", "").lower():
        return "❌ Use on Web Only"

    ip, device = get_client_info()
    method = get_device_type()

    # ----------------------
    # POST (Submit OTP)
    # ----------------------
    if request.method == "POST":

        user_otp = request.form["otp"]

        if not user_otp.isdigit() or len(user_otp) != 6:

            log = Log(
                user=session["user"],
                action="otp access : Invalid Format",
                method=method,
                ip=ip,
                device=device,
                time=str(datetime.datetime.now()),
                status="fail"
            )

            db.session.add(log)
            db.session.commit()

            flash("❌ Invalid format", "danger")
            return redirect("/otp")

        if verify_otp(user_otp):

            session["otp_verified"] = True

            log = Log(
                user=session["user"],
                action="otp access : Successful",
                method=method,
                ip=ip,
                device=device,
                time=str(datetime.datetime.now()),
                status="success"
            )
            db.session.add(log)
            db.session.commit()

            flash("🚪 Door Opened via OTP", "success")
            return redirect("/dashboard")

        else:

            log = Log(
                user=session["user"],
                action="otp access : Incorrect OTP",
                method=method,
                ip=ip,
                device=device,
                time=str(datetime.datetime.now()),
                status="fail"
            )
            db.session.add(log)
            db.session.commit()

            flash("❌ OTP Incorrect", "danger")
            return redirect("/otp")


    return render_template("otp.html")


# ----------------------
# 📊 LOGS
# ----------------------
@app.route("/logs")
def logs():
    all_logs = Log.query.order_by(Log.id.desc()).limit(50).all()
    return render_template("logs.html", logs=all_logs)

@app.route("/logs-data")
def logs_data():
    logs = Log.query.order_by(Log.id.desc()).limit(20).all()

    return jsonify([
        {
            "user": l.user,
            "action": l.action,
            "method": l.method,
            "status": l.status,
            "device": l.device,
            "time": l.time
        } for l in logs
    ])

# ----------------------
# 👑 ADMIN
# ----------------------
@app.route("/admin", methods=["GET", "POST"])
def admin():
    ip, device = get_client_info()
    method = get_device_type()

    if session.get("role") != "admin":
        return "Unauthorized"

    if request.method == "POST":
        user = request.form["username"]
        pw = generate_password_hash(request.form["password"])

        new_user = User(username=user, password=pw, role="user")
        db.session.add(new_user)
        db.session.commit()

        log = Log(
                user=session["user"],
                action="added user : " + session["user"] + " added " + user,
                method=method,
                ip=ip, 
                device=device,
                time=str(datetime.datetime.now()), 
                status="success"
                )
        db.session.add(log)
        db.session.commit()

        flash("✅ User Added", "success")

    users = User.query.all()
    return render_template("admin.html", users=users)

@app.route("/delete-user/<int:user_id>")
def delete_user(user_id):

    ip, device = get_client_info()
    method = get_device_type()

    if session.get("role") != "admin":
        return "Unauthorized"

    user = User.query.get(user_id)
    ip, device = get_client_info()

    if user and user.username == session.get("user"):
        flash("❌ Cannot delete yourself", "danger")
        return redirect("/admin")

    if user:
        db.session.delete(user)
        db.session.commit()

        log = Log(
            user=session["user"],
            action="deleted user : " + session["user"] + " deleted " + user.username,
            method=method,
            ip=ip,
            device=device,
            time=str(datetime.datetime.now()),
            status="success"
        )
        db.session.add(log)
        db.session.commit()

        flash("🗑️ User deleted", "warning")

    return redirect("/admin")

# ----------------------
# LOGOUT
# ----------------------
@app.route("/logout")
def logout():
    ip, device = get_client_info()
    method = get_device_type()
    current_user = session.get("user" , "Unknown")

    log = Log(
        user=current_user,
        action="logout : Logout Successful",
        method=method,
        ip=ip, 
        device=device,
        time=str(datetime.datetime.now()), 
        status="success"
        )

    db.session.add(log)
    db.session.commit()

    session.clear()
    return redirect("/")

# ----------------------
# 🚪 STATUS API (Auto Refresh)
# ----------------------
@app.route("/door-status")
def get_door_status():
    door = Door.query.first()
    return {"status": door.status}

# ----------------------
# INIT DB
# ----------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        if not User.query.first():
            admin_user = User(
                username="admin",
                password=generate_password_hash("1234"),
                role="admin"
            )

            normal_user = User(
                username="user",
                password=generate_password_hash("1111"),
                role="user"
            )

            db.session.add(admin_user)
            db.session.add(normal_user)
            db.session.commit()

    app.run(debug=True)