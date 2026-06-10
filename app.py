import os
import base64
import uuid
from datetime import datetime, date
from zoneinfo import ZoneInfo
from functools import wraps
from math import radians, sin, cos, sqrt, atan2

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import pandas as pd

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

# Default geofence: change these from Admin > Location Settings after first login.
DEFAULT_CENTER_LAT = float(os.environ.get("ALLOWED_CENTER_LAT", "24.2651997"))
DEFAULT_CENTER_LNG = float(os.environ.get("ALLOWED_CENTER_LNG", "55.7314160"))
DEFAULT_RADIUS_M = float(os.environ.get("ALLOWED_RADIUS_METERS", "250"))
DEFAULT_MAX_GPS_ACCURACY_M = float(os.environ.get("MAX_GPS_ACCURACY_METERS", "250"))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(140), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
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
    timestamp_utc = db.Column(db.DateTime, default=uae_now, nullable=False)
    device_time = db.Column(db.String(80), nullable=False)  # Stored as server UAE time, not user device time
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    accuracy = db.Column(db.Float)
    distance_m = db.Column(db.Float)
    photo_path = db.Column(db.String(255), nullable=False)
    user_agent = db.Column(db.Text)
    user = db.relationship("User", backref="attendance_records")

class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)

def get_setting(key, default):
    row = Setting.query.filter_by(key=key).first()
    return row.value if row else str(default)

def set_setting(key, value):
    row = Setting.query.filter_by(key=key).first()
    if row:
        row.value = str(value)
    else:
        db.session.add(Setting(key=key, value=str(value)))
    db.session.commit()

def distance_meters(lat1, lon1, lat2, lon2):
    r = 6371000
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    return r * c

def inside_polygon(lat, lng, polygon):
    # polygon is list of [lat,lng]. Ray casting on lng=x, lat=y.
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

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        user = User.query.get(session["user_id"])
        if not user or user.role != "admin":
            flash("Admin access only.", "danger")
            return redirect(url_for("index"))
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
        return redirect(url_for("attendance"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username, is_active=True).first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            return redirect(url_for("admin_dashboard" if user.role == "admin" else "attendance"))
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
    last_record = Attendance.query.filter_by(user_id=user.id).order_by(Attendance.timestamp_utc.desc()).first()
    next_action = "OUT" if last_record and last_record.action == "IN" else "IN"
    return render_template("attendance.html", records=records, next_action=next_action,
                           center_lat=get_setting("center_lat", DEFAULT_CENTER_LAT),
                           center_lng=get_setting("center_lng", DEFAULT_CENTER_LNG),
                           radius_m=get_setting("radius_m", DEFAULT_RADIUS_M),
                           max_gps_accuracy_m=get_setting("max_gps_accuracy_m", DEFAULT_MAX_GPS_ACCURACY_M),
                           mode=get_setting("geofence_mode", "circle"))

@app.route("/submit-attendance", methods=["POST"])
@login_required
def submit_attendance():
    user = current_user()
    action = request.form.get("action")
    # Never trust browser/device time. Attendance time is generated on the server in UAE time only.
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

    max_accuracy = float(get_setting("max_gps_accuracy_m", DEFAULT_MAX_GPS_ACCURACY_M))
    if accuracy_f is None:
        flash("GPS accuracy is required. Please allow precise location and try again.", "danger")
        return redirect(url_for("attendance"))
    if accuracy_f > max_accuracy:
        flash(f"Blocked: GPS accuracy is too weak ({accuracy_f:.0f} m). Allowed GPS accuracy limit: {max_accuracy:.0f} m. Try again near a window or from a phone.", "danger")
        return redirect(url_for("attendance"))

    allowed, dist = geofence_check(lat_f, lng_f)
    if not allowed:
        flash(f"Blocked: you are outside the allowed location. Distance from center: {dist:.1f} m", "danger")
        return redirect(url_for("attendance"))

    # Prevent repeated same action directly.
    last_record = Attendance.query.filter_by(user_id=user.id).order_by(Attendance.timestamp_utc.desc()).first()
    if last_record and last_record.action == action:
        flash(f"You already signed {'in' if action == 'IN' else 'out'} last. Next action is different.", "warning")
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
        timestamp_utc=system_uae_time
    )
    db.session.add(rec)
    db.session.commit()
    flash(f"Signed {'in' if action == 'IN' else 'out'} successfully using server UAE time, location and camera photo.", "success")
    return redirect(url_for("attendance"))

@app.route("/admin")
@admin_required
def admin_dashboard():
    q_date = request.args.get("date", "")
    user_id = request.args.get("user_id", "")
    query = Attendance.query.join(User)
    if q_date:
        start = datetime.strptime(q_date, "%Y-%m-%d")
        end = datetime.combine(start.date(), datetime.max.time())
        query = query.filter(Attendance.timestamp_utc >= start, Attendance.timestamp_utc <= end)
    if user_id:
        query = query.filter(Attendance.user_id == int(user_id))
    records = query.order_by(Attendance.timestamp_utc.desc()).limit(500).all()
    users = User.query.order_by(User.full_name).all()
    return render_template("admin.html", records=records, users=users, q_date=q_date, user_id=user_id)

@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "user")
        if not username or not full_name or not password:
            flash("Username, full name and password are required.", "danger")
        elif User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
        else:
            u = User(username=username, full_name=full_name, role=role)
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            flash("User created.", "success")
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("users.html", users=users)

@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    if request.method == "POST":
        set_setting("geofence_mode", request.form.get("geofence_mode", "circle"))
        set_setting("center_lat", request.form.get("center_lat", DEFAULT_CENTER_LAT))
        set_setting("center_lng", request.form.get("center_lng", DEFAULT_CENTER_LNG))
        set_setting("radius_m", request.form.get("radius_m", DEFAULT_RADIUS_M))
        set_setting("max_gps_accuracy_m", request.form.get("max_gps_accuracy_m", DEFAULT_MAX_GPS_ACCURACY_M))
        set_setting("polygon", request.form.get("polygon", ""))
        flash("Location settings saved.", "success")
    return render_template("settings.html",
                           geofence_mode=get_setting("geofence_mode", "circle"),
                           center_lat=get_setting("center_lat", DEFAULT_CENTER_LAT),
                           center_lng=get_setting("center_lng", DEFAULT_CENTER_LNG),
                           radius_m=get_setting("radius_m", DEFAULT_RADIUS_M),
                           max_gps_accuracy_m=get_setting("max_gps_accuracy_m", DEFAULT_MAX_GPS_ACCURACY_M),
                           polygon=get_setting("polygon", ""))

@app.route("/admin/export")
@admin_required
def export_excel():
    rows = []
    for r in Attendance.query.join(User).order_by(Attendance.timestamp_utc.desc()).all():
        rows.append({
            "Name": r.user.full_name,
            "Username": r.user.username,
            "Action": "Sign In" if r.action == "IN" else "Sign Out",
            "System UAE Time": r.timestamp_utc.strftime("%Y-%m-%d %H:%M:%S"),
            "Stored Time Source": "Server UAE time",
            "Latitude": r.latitude,
            "Longitude": r.longitude,
            "Accuracy meters": r.accuracy,
            "Distance from allowed center meters": round(r.distance_m or 0, 2),
            "Photo": r.photo_path,
        })
    df = pd.DataFrame(rows)
    out = os.path.join(BASE_DIR, "attendance_export.xlsx")
    df.to_excel(out, index=False)
    return send_file(out, as_attachment=True)

@app.route("/init-db")
def init_db_route():
    init_db()
    return "Database initialized. Default admin: admin / admin123. Please change password after login."

def init_db():
    db.create_all()
    if not Setting.query.filter_by(key="center_lat").first():
        set_setting("center_lat", DEFAULT_CENTER_LAT)
        set_setting("center_lng", DEFAULT_CENTER_LNG)
        set_setting("radius_m", DEFAULT_RADIUS_M)
        set_setting("max_gps_accuracy_m", DEFAULT_MAX_GPS_ACCURACY_M)
        set_setting("geofence_mode", "circle")
        set_setting("polygon", "")
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", full_name="System Admin", role="admin")
        admin.set_password(os.environ.get("ADMIN_PASSWORD", "admin123"))
        db.session.add(admin)
        db.session.commit()

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=True)
