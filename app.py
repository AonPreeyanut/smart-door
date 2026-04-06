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

app = Flask(__name__)

# 🔐 SECRET KEY (ปลอดภัย)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# 🔐 DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

# 🔑 Token
API_TOKEN = secrets.token_hex(16)

# 🚪 Door Status
door_status = "LOCKED"

# 🔢 OTP
OTP_SECRET = os.environ.get("OTP_SECRET") or secrets.token_hex(16)
OTP_INTERVAL = 20  # วินาที

# 🚫 Rate limit (ง่ายๆ)
login_attempts = {}
otp_attempts = {}
otp_blocked_until = {}
otp_request_time = {}

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
        return "mobile"
    else:
        return "web"
    
# 🔢 OTP generate
def generate_otp(counter=None):
    if counter is None:
        counter = int(time.time() // OTP_INTERVAL)

    raw = f"{counter}{OTP_SECRET}"
    hash_val = hashlib.sha256(raw.encode()).hexdigest()
    return str(int(hash_val, 16))[-4:].zfill(4)

# 🔐 secure compare
def secure_compare(a, b):
    return hmac.compare_digest(a, b)

# 🚫 rate limit
def is_blocked(ip):
    now = time.time()
    attempts = login_attempts.get(ip, [])

    # ลบอันเก่า
    attempts = [t for t in attempts if now - t < 60]

    login_attempts[ip] = attempts

    return len(attempts) >= 5

def record_attempt(ip):
    login_attempts.setdefault(ip, []).append(time.time())

def is_otp_blocked(ip):
    now = time.time()

    # ⛔ ยังอยู่ในช่วง cooldown
    if ip in otp_blocked_until and now < otp_blocked_until[ip]:
        return True

    attempts = otp_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < 60]  # 1 นาที
    otp_attempts[ip] = attempts

    return False

def record_otp_attempt(ip):
    now = time.time()
    attempts = otp_attempts.get(ip, [])
    attempts.append(now)

    # ล้างของเก่า
    attempts = [t for t in attempts if now - t < 60]
    otp_attempts[ip] = attempts

    # 🚨 ถ้าผิดเกิน 5 ครั้ง → cooldown
    if len(attempts) >= 5:
        # จำนวนครั้งที่โดน block ก่อนหน้า
        block_count = otp_blocked_until.get(ip, 0)

        # ⏱ Progressive cooldown
        if block_count == 0:
            cooldown = 60     # ครั้งแรก 1 นาที
        elif block_count < now:
            cooldown = 120    # ครั้งสอง 2 นาที
        else:
            cooldown = 300    # ครั้งสาม+ 5 นาที

        otp_blocked_until[ip] = now + cooldown

def get_remaining_block_time(ip):
    now = time.time()
    if ip in otp_blocked_until:
        remaining = int(otp_blocked_until[ip] - now)
        return max(0, remaining)
    return 0

def auto_lock():
    global door_status
    time.sleep(5)
    door_status = "LOCKED"

# ----------------------
# LOGIN
# ----------------------
@app.route("/", methods=["GET", "POST"])
def login():
    ip, device = get_client_info()
    method = get_device_type()

    if request.method == "POST":

        if is_blocked(ip):
            flash("❌ Too many attempts, try later", "danger")
            return redirect("/")

        user = request.form["username"]
        pw = request.form["password"]

        found = User.query.filter_by(username=user).first()

        if found and check_password_hash(found.password, pw):
            session["user"] = user
            session["role"] = found.role

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

            return redirect("/dashboard")

        else:
            record_attempt(ip)

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

    return render_template(
        "dashboard.html",
        role=session.get("role"),
        door_status=door_status,
        token=API_TOKEN
    )

# ----------------------
# 🚪 OPEN DOOR
# ----------------------
@app.route("/open-door")
def open_door():
    global door_status
    ip, device = get_client_info()
    token = request.args.get("token")
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

    door_status = "UNLOCKED"

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

    global door_status
    door_status = "LOCKED"
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
def request_otp():
    if get_device_type() != "mobile":
        return "❌ Mobile Only"
    
    ip, _ = get_client_info()
    now = time.time()

    last = otp_request_time.get(ip, 0)

    if now - last < 10:
        return "⛔ Please wait before requesting again"

    otp_request_time[ip] = now

    otp = generate_otp()
    return render_template("request_otp.html", otp=otp)

# ----------------------
# 🔢 ENTER OTP (Web)
# ----------------------
@app.route("/otp", methods=["GET", "POST"])
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

        if is_otp_blocked(ip):
            remaining = get_remaining_block_time(ip)

            log = Log(
                user=session["user"],
                action="otp access : Blocked due to too many attempts",
                method=method,
                ip=ip,
                device=device,
                time=str(datetime.datetime.now()),
                status="fail"
            )

            db.session.add(log)
            db.session.commit()


            flash(f"⛔ Try again in {remaining} sec", "danger")
            return redirect("/otp")

        user_otp = request.form["otp"]

        if not user_otp.isdigit() or len(user_otp) != 4:

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

        current_otp = generate_otp()
        previous = generate_otp(int(time.time() // OTP_INTERVAL) - 1)

        if secure_compare(user_otp, current_otp) or secure_compare(user_otp, previous):

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

            otp_attempts[ip] = []

            flash("🚪 Door Opened via OTP", "success")
            return redirect("/dashboard")

        else:
            record_otp_attempt(ip)

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

    # ----------------------
    # GET (เปิดหน้า OTP)
    # ----------------------
    remaining = get_remaining_block_time(ip)
    return render_template("otp.html", remaining=remaining)


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

    log = Log(
        user=session["user"],
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
    return {"status": door_status}

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