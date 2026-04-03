from flask import Flask, render_template, request, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
import datetime
import secrets
import time
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
from flask import jsonify

app = Flask(__name__)
app.secret_key = "secret123"

# 🔐 DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

# 🔑 Token
API_TOKEN = secrets.token_hex(16)

# 🚪 Door Status
door_status = "LOCKED"

# เก็บ OTP ก่อนหน้า
last_otp = None

# 🔢 OTP (เปลี่ยนทุก 20 วิ)
def generate_otp():
    current_time = int(time.time() // 20)
    raw = str(current_time) + "MY_SECRET_SALT"
    hash_val = hashlib.sha256(raw.encode()).hexdigest()
    otp = str(int(hash_val, 16))[-4:]
    return otp.zfill(4)

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
# LOGIN
# ----------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form["username"]
        pw = request.form["password"]

        found = User.query.filter_by(username=user).first()
        ip, device = get_client_info()
        method = get_device_type()

        if found and check_password_hash(found.password, pw):
            session["user"] = user
            session["role"] = found.role

            log = Log(
                user=user,
                action="login",
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
            flash("❌ Login Failed", "danger")

            log = Log(
                user=user,
                action="login",
                method=method,
                ip=ip,
                device=device,
                time=str(datetime.datetime.now()),
                status="fail"
            )
            db.session.add(log)
            db.session.commit()

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

    if "user" not in session:
        return redirect("/")

    token = request.args.get("token")
    source = get_device_type()

    if token != API_TOKEN:
        flash("❌ Invalid token!", "danger")
        return redirect("/dashboard")

    door_status = "UNLOCKED"

    ip, device = get_client_info()

    log = Log(
        user=session["user"],
        action="open_door",
        method=source,
        ip=ip,
        device=device,
        time=str(datetime.datetime.now()),
        status="success"
    )
    db.session.add(log)
    db.session.commit()

    flash(f"🚪 Door Opened via {source}", "success")
    return redirect("/dashboard")

# ----------------------
# 🔒 CLOSE DOOR
# ----------------------
@app.route("/close-door")
def close_door():
    global door_status
    door_status = "LOCKED"
    source = get_device_type()

    ip, device = get_client_info()

    log = Log(
        user=session["user"],
        action="close_door",
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
    otp = generate_otp()
    return render_template("request_otp.html", otp=otp)

# ----------------------
# 🔢 ENTER OTP (Web)
# ----------------------
@app.route("/otp", methods=["GET", "POST"])
def otp():
    global door_status

    if "user" not in session:
        return redirect("/")

    user_agent = request.headers.get("User-Agent", "").lower()

    if "mobile" in user_agent:
        return "❌ Use on Web Only"

    if request.method == "POST":
        user_otp = request.form["otp"]

        current_otp = generate_otp()
        prev_otp = str(int(hashlib.sha256((str(int(time.time() // 20) - 1) + "MY_SECRET_SALT").encode()).hexdigest(), 16))[-4:]

        if user_otp == current_otp or user_otp == prev_otp:
            door_status = "UNLOCKED"

            ip, device = get_client_info()

            log = Log(
                user=session["user"],
                action="otp_access",
                method="otp",
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
            flash("❌ OTP Incorrect", "danger")

            ip, device = get_client_info()

            log = Log(
                user=session["user"],
                action="otp_access",
                method="otp",
                ip=ip,
                device=device,
                time=str(datetime.datetime.now()),
                status="fail"
            )
            db.session.add(log)
            db.session.commit()

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
    if session.get("role") != "admin":
        return "Unauthorized"

    if request.method == "POST":
        user = request.form["username"]
        pw = generate_password_hash(request.form["password"])

        new_user = User(username=user, password=pw, role="user")
        db.session.add(new_user)
        db.session.commit()

        flash("✅ User Added", "success")

    users = User.query.all()
    return render_template("admin.html", users=users)

@app.route("/delete-user/<int:user_id>")
def delete_user(user_id):
    if session.get("role") != "admin":
        return "Unauthorized"

    user = User.query.get(user_id)

    if user and user.username == session.get("user"):
        flash("❌ Cannot delete yourself", "danger")
        return redirect("/admin")

    if user:
        db.session.delete(user)
        db.session.commit()
        flash("🗑️ User deleted", "warning")

    return redirect("/admin")

# ----------------------
# LOGOUT
# ----------------------
@app.route("/logout")
def logout():
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
            admin = User(
                username="admin",
                password=generate_password_hash("1234"),
                role="admin"
            )
            db.session.add(admin)
            db.session.commit()

    app.run(debug=True)