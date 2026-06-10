import os
import base64
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo
from functools import wraps
from math import radians, sin, cos, sqrt, atan2

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text, func
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import pandas as pd
import requests

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
CAPTURE_DIR = os.path.join(BASE_DIR, "static", "captures")
os.makedirs(CAPTURE_DIR, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///attendance.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

UAE_TZ = ZoneInfo("Asia/Dubai")

def uae_now():
    """Server-side UAE time. Do not trust device/browser time for attendance."""
    return datetime.now(UAE_TZ).replace(tzinfo=None)

DEFAULT_CENTER_LAT = float(os.environ.get("ALLOWED_CENTER_LAT", "24.2651997"))
DEFAULT_CENTER_LNG = float(os.environ.get("ALLOWED_CENTER_LNG", "55.7314160"))
DEFAULT_RADIUS_M = float(os.environ.get("ALLOWED_RADIUS_METERS", "250"))
DEFAULT_MAX_GPS_ACCURACY_M = float(os.environ.get("MAX_GPS_ACCURACY_METERS", "250"))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(140), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # user, admin, owner
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=uae_now)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    action = db.Column(db.String(20), nullable=False)  # IN or OUT
    timestamp_utc = db.Column(db.DateTime, default=uae_now, nullable=False)  # actually server UAE time
    device_time = db.Column(db.String(80), nullable=False)  # stored as server UAE time label
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    accuracy = db.Column(db.Float)
    distance_m = db.Column(db.Float)
    photo_path = db.Column(db.String(255), nullable=False)
    user_agent = db.Column(db.Text)
    ip_address = db.Column(db.String(80))
    ip_country = db.Column(db.String(80))
    ip_org = db.Column(db.String(255))
    ip_is_vpn = db.Column(db.Boolean, default=False)
    ip_is_hosting = db.Column(db.Boolean, default=False)
    security_status = db.Column(db.String(255))
    is_manual = db.Column(db.Boolean, default=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    updated_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    updated_at = db.Column(db.DateTime)
    note = db.Column(db.Text)
    user = db.relationship("User", foreign_keys=[user_id], backref="attendance_records")
    created_by = db.relationship("User", foreign_keys=[created_by_id])
    updated_by = db.relationship("User", foreign_keys=[updated_by_id])

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    action = db.Column(db.String(80), nullable=False)
    target_type = db.Column(db.String(80), nullable=False)
    target_id = db.Column(db.Integer)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(80))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=uae_now)
    actor = db.relationship("User")

class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)

def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.headers.get("X-Real-IP") or request.remote_addr or ""


def is_private_or_local_ip(ip):
    if not ip:
        return True
    return (
        ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or
        ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.") or
        ip.startswith("172.19.") or ip.startswith("172.2") or ip.startswith("172.30.") or
        ip.startswith("172.31.") or ip == "::1"
    )

def ip_security_check(ip):
    """Best-effort VPN/proxy/datacenter check. Blocks only if settings say so.
    Uses proxycheck.io when PROXYCHECK_API_KEY is set; otherwise falls back to ip-api.com.
    """
    result = {
        "checked": False,
        "blocked": False,
        "reason": "IP security check not completed.",
        "country": "",
        "org": "",
        "is_vpn": False,
        "is_hosting": False,
    }
    enabled = get_setting("vpn_check_enabled", "1") == "1"
    block_enabled = get_setting("vpn_block_enabled", "1") == "1"
    block_hosting = get_setting("block_hosting_provider", "1") == "1"
    block_non_uae = get_setting("block_non_uae_ip", "0") == "1"
    if not enabled:
        result["reason"] = "IP security check disabled by System Owner."
        return result
    if is_private_or_local_ip(ip):
        result["reason"] = "Private/local IP. VPN check skipped."
        return result
    try:
        key = os.environ.get("PROXYCHECK_API_KEY", "").strip()
        if key:
            url = f"https://proxycheck.io/v2/{ip}?key={key}&vpn=1&asn=1&risk=1&tag=attendance"
            data = requests.get(url, timeout=4).json()
            item = data.get(ip, {}) if isinstance(data, dict) else {}
            result["checked"] = True
            result["country"] = item.get("country", "") or item.get("isocode", "")
            result["org"] = item.get("provider", "") or item.get("organisation", "") or item.get("asn", "")
            proxy_value = str(item.get("proxy", "no")).lower()
            result["is_vpn"] = proxy_value in ["yes", "true", "1"]
            result["is_hosting"] = "hosting" in str(item.get("type", "")).lower() or "datacenter" in str(item.get("type", "")).lower()
        else:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,countryCode,country,isp,org,as,proxy,hosting,mobile,query"
            data = requests.get(url, timeout=4).json()
            result["checked"] = data.get("status") == "success"
            result["country"] = data.get("countryCode", "") or data.get("country", "")
            result["org"] = data.get("org") or data.get("isp") or data.get("as", "")
            result["is_vpn"] = bool(data.get("proxy"))
            result["is_hosting"] = bool(data.get("hosting"))
    except Exception as exc:
        result["reason"] = f"IP security check failed: {exc}"
        return result

    reasons = []
    if result["is_vpn"]:
        reasons.append("VPN/proxy IP detected")
    if block_hosting and result["is_hosting"]:
        reasons.append("datacenter/hosting IP detected")
    if block_non_uae and result["country"] and result["country"] not in ["AE", "United Arab Emirates"]:
        reasons.append(f"IP country is {result['country']}, not UAE")
    result["reason"] = "; ".join(reasons) if reasons else "IP security check passed."
    result["blocked"] = block_enabled and bool(reasons)
    return result

def audit(action, target_type, target_id=None, details=""):
    actor_id = session.get("user_id")
    if not actor_id:
        return
    db.session.add(AuditLog(
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details,
        ip_address=get_client_ip(),
        user_agent=request.headers.get("User-Agent", ""),
    ))

def get_setting(key, default):
    row = Setting.query.filter_by(key=key).first()
    return row.value if row else str(default)

def set_setting(key, value):
    row = Setting.query.filter_by(key=key).first()
    if row:
        row.value = str(value)
    else:
        db.session.add(Setting(key=key, value=str(value)))

def distance_meters(lat1, lon1, lat2, lon2):
    r = 6371000
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    return r * c

def inside_polygon(lat, lng, polygon):
    x, y = lng, lat
    inside = False
    n = len(polygon)
    if n < 3:
        return False
    p1y, p1x = polygon[0][0], polygon[0][1]
    for i in range(n + 1):
        p2y, p2x = polygon[i % n][0], polygon[i % n][1]
        if y > min(p1y, p2y):
            if y <= max(p1y, p2y):
                if x <= max(p1x, p2x):
                    if p1y != p2y:
                        xinters = (y - p1y) * (p2x - p1x) / (p2y - p1y) + p1x
                    if p1x == p2x or x <= xinters:
                        inside = not inside
        p1y, p1x = p2y, p2x
    return inside

def geofence_check(lat, lng):
    mode = get_setting("geofence_mode", "circle")
    center_lat = float(get_setting("center_lat", DEFAULT_CENTER_LAT))
    center_lng = float(get_setting("center_lng", DEFAULT_CENTER_LNG))
    radius = float(get_setting("radius_m", DEFAULT_RADIUS_M))
    dist = distance_meters(center_lat, center_lng, lat, lng)
    if mode == "polygon":
        raw = get_setting("polygon", "")
        polygon = []
        for part in raw.split(";"):
            if "," in part:
                a, b = part.strip().split(",", 1)
                polygon.append([float(a), float(b)])
        return inside_polygon(lat, lng, polygon), dist
    return dist <= radius, dist

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def view_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        user = User.query.get(session["user_id"])
        if not user or user.role not in ["admin", "owner"]:
            flash("Admin access only.", "danger")
            return redirect(url_for("attendance"))
        return fn(*args, **kwargs)
    return wrapper

def owner_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        user = User.query.get(session["user_id"])
        if not user or user.role != "owner":
            flash("System Owner access only.", "danger")
            return redirect(url_for("admin_dashboard"))
        return fn(*args, **kwargs)
    return wrapper

def current_user():
    if session.get("user_id"):
        return User.query.get(session["user_id"])
    return None

@app.context_processor
def inject_user():
    return {"current_user": current_user()}

@app.route("/")
def index():
    if session.get("user_id"):
        user = current_user()
        if user and user.role in ["admin", "owner"]:
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("attendance"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        # Username login is case-insensitive. Password remains case-sensitive.
        user = User.query.filter(func.lower(User.username) == username.lower(), User.is_active == True).first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            return redirect(url_for("admin_dashboard" if user.role in ["admin", "owner"] else "attendance"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/attendance")
@login_required
def attendance():
    user = current_user()
    today_start = datetime.combine(uae_now().date(), datetime.min.time())
    records = Attendance.query.filter(Attendance.user_id == user.id, Attendance.timestamp_utc >= today_start).order_by(Attendance.timestamp_utc.desc()).all()
    has_in_today = any(r.action == "IN" for r in records)
    has_out_today = any(r.action == "OUT" for r in records)
    can_sign_in = not has_in_today
    can_sign_out = has_in_today and not has_out_today
    return render_template("attendance.html", records=records, can_sign_in=can_sign_in, can_sign_out=can_sign_out,
                           center_lat=get_setting("center_lat", DEFAULT_CENTER_LAT),
                           center_lng=get_setting("center_lng", DEFAULT_CENTER_LNG),
                           radius_m=get_setting("radius_m", DEFAULT_RADIUS_M),
                           max_gps_accuracy_m=get_setting("max_gps_accuracy_m", DEFAULT_MAX_GPS_ACCURACY_M),
                           mode=get_setting("geofence_mode", "circle"))


@app.route("/security-status")
@login_required
def security_status():
    ip = get_client_ip()
    risk = ip_security_check(ip)
    return {
        "ip": ip,
        "checked": risk["checked"],
        "blocked": risk["blocked"],
        "reason": risk["reason"],
        "country": risk["country"],
        "org": risk["org"],
        "is_vpn": risk["is_vpn"],
        "is_hosting": risk["is_hosting"],
    }

@app.route("/submit-attendance", methods=["POST"])
@login_required
def submit_attendance():
    user = current_user()
    action = request.form.get("action")
    system_uae_time = uae_now()
    device_time = system_uae_time.strftime("%Y-%m-%d %H:%M:%S")
    lat = request.form.get("latitude")
    lng = request.form.get("longitude")
    accuracy = request.form.get("accuracy") or None
    photo_data = request.form.get("photo_data", "")

    if action not in ["IN", "OUT"]:
        flash("Invalid attendance action.", "danger")
        return redirect(url_for("attendance"))
    if not lat or not lng:
        flash("Location is required. Please allow location permission.", "danger")
        return redirect(url_for("attendance"))
    if not photo_data.startswith("data:image"):
        flash("Camera photo is required. Sign in/out is blocked without a photo.", "danger")
        return redirect(url_for("attendance"))

    try:
        lat_f, lng_f = float(lat), float(lng)
        accuracy_f = float(accuracy) if accuracy else None
    except ValueError:
        flash("Invalid location data. Please refresh and try again.", "danger")
        return redirect(url_for("attendance"))

    ip_risk = ip_security_check(get_client_ip())
    if ip_risk.get("blocked"):
        flash(f"Blocked: VPN/proxy/datacenter IP detected. {ip_risk.get('reason')} Please turn off VPN and use the normal local network.", "danger")
        return redirect(url_for("attendance"))

    max_accuracy = float(get_setting("max_gps_accuracy_m", DEFAULT_MAX_GPS_ACCURACY_M))
    if accuracy_f is None:
        flash("GPS accuracy is required. Please allow precise location and try again.", "danger")
        return redirect(url_for("attendance"))
    if accuracy_f > max_accuracy:
        flash(f"Blocked: GPS accuracy is too weak ({accuracy_f:.0f} m). Allowed GPS accuracy limit: {max_accuracy:.0f} m.", "danger")
        return redirect(url_for("attendance"))

    allowed, dist = geofence_check(lat_f, lng_f)
    if not allowed:
        flash(f"Blocked: you are outside the allowed location. Distance from center: {dist:.1f} m", "danger")
        return redirect(url_for("attendance"))

    today_start = datetime.combine(system_uae_time.date(), datetime.min.time())
    today_records = Attendance.query.filter(Attendance.user_id == user.id, Attendance.timestamp_utc >= today_start).all()
    has_in_today = any(r.action == "IN" for r in today_records)
    has_out_today = any(r.action == "OUT" for r in today_records)
    if action == "IN" and has_in_today:
        flash("Blocked: you already signed in today. Duplicate sign-in is not allowed.", "warning")
        return redirect(url_for("attendance"))
    if action == "OUT" and not has_in_today:
        flash("Blocked: you cannot sign out because you did not sign in today.", "warning")
        return redirect(url_for("attendance"))
    if action == "OUT" and has_out_today:
        flash("Blocked: you already signed out today. Duplicate sign-out is not allowed.", "warning")
        return redirect(url_for("attendance"))

    header, encoded = photo_data.split(",", 1)
    image_bytes = base64.b64decode(encoded)
    filename = secure_filename(f"{user.username}_{action}_{system_uae_time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}.jpg")
    file_path = os.path.join(CAPTURE_DIR, filename)
    with open(file_path, "wb") as f:
        f.write(image_bytes)

    rec = Attendance(
        user_id=user.id,
        action=action,
        device_time=device_time,
        latitude=lat_f,
        longitude=lng_f,
        accuracy=accuracy_f,
        distance_m=dist,
        photo_path=f"captures/{filename}",
        user_agent=request.headers.get("User-Agent", ""),
        ip_address=get_client_ip(),
        ip_country=ip_risk.get("country", ""),
        ip_org=ip_risk.get("org", ""),
        ip_is_vpn=ip_risk.get("is_vpn", False),
        ip_is_hosting=ip_risk.get("is_hosting", False),
        security_status=ip_risk.get("reason", ""),
        timestamp_utc=system_uae_time,
        is_manual=False,
    )
    db.session.add(rec)
    db.session.commit()
    flash(f"Signed {'in' if action == 'IN' else 'out'} successfully using server UAE time, location and camera photo.", "success")
    return redirect(url_for("attendance"))

@app.route("/admin")
@view_required
def admin_dashboard():
    q_date = request.args.get("date", "")
    user_id = request.args.get("user_id", "")
    query = Attendance.query.join(User, Attendance.user_id == User.id)
    if q_date:
        start = datetime.strptime(q_date, "%Y-%m-%d")
        end = datetime.combine(start.date(), datetime.max.time())
        query = query.filter(Attendance.timestamp_utc >= start, Attendance.timestamp_utc <= end)
    if user_id:
        query = query.filter(Attendance.user_id == int(user_id))
    records = query.order_by(Attendance.timestamp_utc.desc()).limit(500).all()
    users = User.query.order_by(User.full_name).all()
    return render_template("admin.html", records=records, users=users, q_date=q_date, user_id=user_id)

@app.route("/owner/manual", methods=["GET", "POST"])
@owner_required
def owner_manual_record():
    if request.method == "POST":
        user_id = int(request.form.get("user_id"))
        action = request.form.get("action")
        timestamp_text = request.form.get("timestamp")
        lat_f = float(request.form.get("latitude") or DEFAULT_CENTER_LAT)
        lng_f = float(request.form.get("longitude") or DEFAULT_CENTER_LNG)
        accuracy_f = float(request.form.get("accuracy") or 0)
        note = request.form.get("note", "")
        photo = request.files.get("photo")
        if action not in ["IN", "OUT"] or not timestamp_text or not photo:
            flash("User, action, UAE time, and photo are required.", "danger")
            return redirect(url_for("owner_manual_record"))
        try:
            ts = datetime.strptime(timestamp_text, "%Y-%m-%dT%H:%M")
        except ValueError:
            flash("Invalid UAE time format.", "danger")
            return redirect(url_for("owner_manual_record"))
        _, dist = geofence_check(lat_f, lng_f)
        filename = secure_filename(f"manual_{user_id}_{action}_{ts.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}_{photo.filename}")
        path = os.path.join(CAPTURE_DIR, filename)
        photo.save(path)
        rec = Attendance(
            user_id=user_id,
            action=action,
            timestamp_utc=ts,
            device_time=ts.strftime("%Y-%m-%d %H:%M:%S"),
            latitude=lat_f,
            longitude=lng_f,
            accuracy=accuracy_f,
            distance_m=dist,
            photo_path=f"captures/{filename}",
            user_agent="Manual owner entry",
            ip_address=get_client_ip(),
            ip_country="OWNER_MANUAL",
            ip_org="Owner manual entry",
            ip_is_vpn=False,
            ip_is_hosting=False,
            security_status="Owner manual entry - security bypass recorded in audit log",
            is_manual=True,
            created_by_id=session["user_id"],
            note=note,
        )
        db.session.add(rec)
        db.session.flush()
        audit("manual_add_attendance", "attendance", rec.id, f"Added {action} for user_id={user_id} at UAE time {ts}")
        db.session.commit()
        flash("Manual attendance record added by System Owner.", "success")
        return redirect(url_for("admin_dashboard"))
    users = User.query.filter_by(is_active=True).order_by(User.full_name).all()
    now_value = uae_now().strftime("%Y-%m-%dT%H:%M")
    return render_template("manual_record.html", users=users, now_value=now_value,
                           default_lat=DEFAULT_CENTER_LAT, default_lng=DEFAULT_CENTER_LNG)

@app.route("/owner/attendance/<int:record_id>/edit", methods=["GET", "POST"])
@owner_required
def owner_edit_record(record_id):
    rec = Attendance.query.get_or_404(record_id)
    if request.method == "POST":
        old = f"user_id={rec.user_id}, action={rec.action}, time={rec.timestamp_utc}, lat={rec.latitude}, lng={rec.longitude}"
        rec.user_id = int(request.form.get("user_id"))
        rec.action = request.form.get("action")
        ts = datetime.strptime(request.form.get("timestamp"), "%Y-%m-%dT%H:%M")
        rec.timestamp_utc = ts
        rec.device_time = ts.strftime("%Y-%m-%d %H:%M:%S")
        rec.latitude = float(request.form.get("latitude"))
        rec.longitude = float(request.form.get("longitude"))
        rec.accuracy = float(request.form.get("accuracy") or 0)
        _, rec.distance_m = geofence_check(rec.latitude, rec.longitude)
        rec.note = request.form.get("note", "")
        rec.is_manual = True
        rec.updated_by_id = session["user_id"]
        rec.updated_at = uae_now()
        photo = request.files.get("photo")
        if photo and photo.filename:
            filename = secure_filename(f"edit_{rec.id}_{uuid.uuid4().hex[:8]}_{photo.filename}")
            path = os.path.join(CAPTURE_DIR, filename)
            photo.save(path)
            rec.photo_path = f"captures/{filename}"
        audit("manual_edit_attendance", "attendance", rec.id, old)
        db.session.commit()
        flash("Attendance record updated by System Owner.", "success")
        return redirect(url_for("admin_dashboard"))
    users = User.query.filter_by(is_active=True).order_by(User.full_name).all()
    return render_template("edit_record.html", rec=rec, users=users)

@app.route("/owner/audit")
@owner_required
def owner_audit():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(500).all()
    return render_template("audit.html", logs=logs)

@app.route("/admin/users", methods=["GET", "POST"])
@owner_required
def admin_users():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "user")
        if role not in ["user", "admin", "owner"]:
            role = "user"
        if not username or not full_name or not password:
            flash("Username, full name and password are required.", "danger")
        elif User.query.filter(func.lower(User.username) == username.lower()).first():
            flash("Username already exists. Usernames are not case-sensitive.", "danger")
        else:
            u = User(username=username, full_name=full_name, role=role)
            u.set_password(password)
            db.session.add(u)
            db.session.flush()
            audit("create_user", "user", u.id, f"Created username={username}, role={role}")
            db.session.commit()
            flash("User created.", "success")
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("users.html", users=users)

@app.route("/admin/settings", methods=["GET", "POST"])
@owner_required
def admin_settings():
    if request.method == "POST":
        set_setting("geofence_mode", request.form.get("geofence_mode", "circle"))
        set_setting("center_lat", request.form.get("center_lat", DEFAULT_CENTER_LAT))
        set_setting("center_lng", request.form.get("center_lng", DEFAULT_CENTER_LNG))
        set_setting("radius_m", request.form.get("radius_m", DEFAULT_RADIUS_M))
        set_setting("max_gps_accuracy_m", request.form.get("max_gps_accuracy_m", DEFAULT_MAX_GPS_ACCURACY_M))
        set_setting("polygon", request.form.get("polygon", ""))
        set_setting("vpn_check_enabled", "1" if request.form.get("vpn_check_enabled") else "0")
        set_setting("vpn_block_enabled", "1" if request.form.get("vpn_block_enabled") else "0")
        set_setting("block_hosting_provider", "1" if request.form.get("block_hosting_provider") else "0")
        set_setting("block_non_uae_ip", "1" if request.form.get("block_non_uae_ip") else "0")
        audit("update_settings", "settings", None, "Location/geofence/security settings updated")
        db.session.commit()
        flash("Location settings saved.", "success")
    return render_template("settings.html",
                           geofence_mode=get_setting("geofence_mode", "circle"),
                           center_lat=get_setting("center_lat", DEFAULT_CENTER_LAT),
                           center_lng=get_setting("center_lng", DEFAULT_CENTER_LNG),
                           radius_m=get_setting("radius_m", DEFAULT_RADIUS_M),
                           max_gps_accuracy_m=get_setting("max_gps_accuracy_m", DEFAULT_MAX_GPS_ACCURACY_M),
                           polygon=get_setting("polygon", ""),
                           vpn_check_enabled=get_setting("vpn_check_enabled", "1"),
                           vpn_block_enabled=get_setting("vpn_block_enabled", "1"),
                           block_hosting_provider=get_setting("block_hosting_provider", "1"),
                           block_non_uae_ip=get_setting("block_non_uae_ip", "0"))

@app.route("/admin/export")
@view_required
def export_excel():
    rows = []
    for r in Attendance.query.join(User, Attendance.user_id == User.id).order_by(Attendance.timestamp_utc.desc()).all():
        rows.append({
            "Name": r.user.full_name,
            "Username": r.user.username,
            "Action": "Sign In" if r.action == "IN" else "Sign Out",
            "System UAE Time": r.timestamp_utc.strftime("%Y-%m-%d %H:%M:%S"),
            "Stored Time Source": "Server UAE time" if not r.is_manual else "Manual owner entry/correction",
            "Latitude": r.latitude,
            "Longitude": r.longitude,
            "Accuracy meters": r.accuracy,
            "Distance from allowed center meters": round(r.distance_m or 0, 2),
            "IP Address": r.ip_address,
            "IP Country": r.ip_country or "",
            "IP Organization": r.ip_org or "",
            "VPN/Proxy Detected": "Yes" if r.ip_is_vpn else "No",
            "Datacenter/Hosting Detected": "Yes" if r.ip_is_hosting else "No",
            "Security Status": r.security_status or "",
            "Manual Record": "Yes" if r.is_manual else "No",
            "Created By": r.created_by.full_name if r.created_by else "User self sign-in/out",
            "Updated By": r.updated_by.full_name if r.updated_by else "",
            "Note": r.note or "",
            "Photo": r.photo_path,
        })
    df = pd.DataFrame(rows)
    out = os.path.join(BASE_DIR, "attendance_export.xlsx")
    df.to_excel(out, index=False)
    return send_file(out, as_attachment=True)

@app.route("/init-db")
def init_db_route():
    init_db()
    return "Database initialized. Default admin: admin / admin123. System Owner: Ahmad / configured owner password."

def ensure_schema_upgrades():
    """Lightweight startup migration for existing Railway/PostgreSQL or SQLite databases."""
    inspector = inspect(db.engine)
    if "attendance" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("attendance")}
    dialect = db.engine.dialect.name
    if dialect == "postgresql":
        ddl = {
            "ip_address": "ALTER TABLE attendance ADD COLUMN ip_address VARCHAR(80)",
            "is_manual": "ALTER TABLE attendance ADD COLUMN is_manual BOOLEAN DEFAULT FALSE",
            "created_by_id": "ALTER TABLE attendance ADD COLUMN created_by_id INTEGER",
            "updated_by_id": "ALTER TABLE attendance ADD COLUMN updated_by_id INTEGER",
            "updated_at": "ALTER TABLE attendance ADD COLUMN updated_at TIMESTAMP",
            "note": "ALTER TABLE attendance ADD COLUMN note TEXT",
            "ip_country": "ALTER TABLE attendance ADD COLUMN ip_country VARCHAR(80)",
            "ip_org": "ALTER TABLE attendance ADD COLUMN ip_org VARCHAR(255)",
            "ip_is_vpn": "ALTER TABLE attendance ADD COLUMN ip_is_vpn BOOLEAN DEFAULT 0",
            "ip_is_hosting": "ALTER TABLE attendance ADD COLUMN ip_is_hosting BOOLEAN DEFAULT 0",
            "security_status": "ALTER TABLE attendance ADD COLUMN security_status VARCHAR(255)",
            "ip_country": "ALTER TABLE attendance ADD COLUMN ip_country VARCHAR(80)",
            "ip_org": "ALTER TABLE attendance ADD COLUMN ip_org VARCHAR(255)",
            "ip_is_vpn": "ALTER TABLE attendance ADD COLUMN ip_is_vpn BOOLEAN DEFAULT FALSE",
            "ip_is_hosting": "ALTER TABLE attendance ADD COLUMN ip_is_hosting BOOLEAN DEFAULT FALSE",
            "security_status": "ALTER TABLE attendance ADD COLUMN security_status VARCHAR(255)",
        }
    else:
        ddl = {
            "ip_address": "ALTER TABLE attendance ADD COLUMN ip_address VARCHAR(80)",
            "is_manual": "ALTER TABLE attendance ADD COLUMN is_manual BOOLEAN DEFAULT 0",
            "created_by_id": "ALTER TABLE attendance ADD COLUMN created_by_id INTEGER",
            "updated_by_id": "ALTER TABLE attendance ADD COLUMN updated_by_id INTEGER",
            "updated_at": "ALTER TABLE attendance ADD COLUMN updated_at DATETIME",
            "note": "ALTER TABLE attendance ADD COLUMN note TEXT",
        }
    for col, stmt in ddl.items():
        if col not in existing:
            db.session.execute(text(stmt))
    db.session.commit()

def init_db():
    db.create_all()
    ensure_schema_upgrades()
    if not Setting.query.filter_by(key="center_lat").first():
        set_setting("center_lat", DEFAULT_CENTER_LAT)
        set_setting("center_lng", DEFAULT_CENTER_LNG)
        set_setting("radius_m", DEFAULT_RADIUS_M)
        set_setting("max_gps_accuracy_m", DEFAULT_MAX_GPS_ACCURACY_M)
        set_setting("geofence_mode", "circle")
        set_setting("polygon", "")
        set_setting("vpn_check_enabled", "1")
        set_setting("vpn_block_enabled", "1")
        set_setting("block_hosting_provider", "1")
        set_setting("block_non_uae_ip", "0")
        db.session.commit()
    if not User.query.filter(func.lower(User.username) == "admin").first():
        admin = User(username="admin", full_name="System Admin", role="admin")
        admin.set_password(os.environ.get("ADMIN_PASSWORD", "admin123"))
        db.session.add(admin)
        db.session.commit()
    if not User.query.filter(func.lower(User.username) == "ahmad").first():
        owner = User(username="Ahmad", full_name="Ahmad - System Owner", role="owner")
        owner.set_password(os.environ.get("OWNER_PASSWORD", "Ahna@@@$$$"))
        db.session.add(owner)
        db.session.commit()

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=True)
