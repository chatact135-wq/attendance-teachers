# Geo Attendance App

Ready-to-publish Flask attendance system with:

- User sign in / sign out
- Required browser location permission
- Required camera photo before every sign in/out
- Location restriction by circle radius or square/polygon
- Admin dashboard for records
- Admin user creation
- Admin location settings
- GPS accuracy blocking
- Google Maps link for each record
- Excel export
- Saved photos for every sign in/out

## Default login

Username: `admin`  
Password: `admin123`

Change this after first login by creating a new admin user or setting `ADMIN_PASSWORD` before first run.

## Deploy on Render

1. Upload this folder to GitHub.
2. Create a new Render Web Service.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`
5. Add environment variable:
   - `SECRET_KEY` = any long random text
   - Optional: `ADMIN_PASSWORD` = your first admin password
6. Open `/init-db` once if needed.
7. Login at `/login`.
8. Default location is already set to 24.2651997, 55.7314160 with a 250 meter radius. You can change it from Admin > Location Settings.

## Important

- Browser camera and location work best on HTTPS. Render provides HTTPS.
- Laptop location may be less accurate than phone GPS. This version blocks readings worse than 100 meters accuracy by default.
- Circle radius is more reliable than exact square.
- For square mode, enter corners like:

`24.0001,54.0001;24.0001,54.0009;24.0009,54.0009;24.0009,54.0001`

## Local test

```bash
pip install -r requirements.txt
python app.py
```

Then open: `http://127.0.0.1:5000`


## Default geofence in this package

- Latitude: 24.2651997
- Longitude: 55.7314160
- Radius: 250 meters
- Maximum accepted GPS accuracy: 100 meters

## Database and photo storage

Default database: SQLite file `instance/attendance.db` when using the default Flask SQLite URI.

Photos are saved inside `static/captures/`. This is fine for testing, but for production with many users, use PostgreSQL for records and external image storage such as Cloudinary, S3, or Firebase Storage.


Update in this version:
- Allowed radius remains 250 meters.
- GPS accuracy limit default changed from 100 meters to 250 meters.
- Admin can dynamically edit both radius and GPS accuracy from Admin > Location Settings.

## Time handling
This version does not trust the user's device time. Sign-in and sign-out timestamps are generated on the server using UAE time zone only (`Asia/Dubai`, UTC+4). Admin pages and Excel export display System UAE Time.

## VPN / Proxy / Fake GPS Protection Update

This version adds a server-side IP security check:
- Blocks many VPN/proxy IP addresses.
- Blocks datacenter/hosting IP addresses when enabled.
- Optionally blocks non-UAE IP addresses.
- Shows a warning/popup on the attendance page when IP risk is detected.
- Stores IP country, organization, VPN/proxy risk, hosting risk, and security status in attendance records and Excel export.

For stronger VPN detection, create a free/paid ProxyCheck account and add this Railway environment variable:

PROXYCHECK_API_KEY=your_key_here

Without PROXYCHECK_API_KEY, the system uses a basic fallback IP check.

Important: A normal website cannot 100% detect fake GPS/mock-location apps. For highest security, combine GPS + camera photo + VPN/IP check + daily QR code inside the school/office.
