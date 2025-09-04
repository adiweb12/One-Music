
import os import re import uuid from datetime import datetime, timedelta, timezone

from flask import Flask, request, jsonify from flask_cors import CORS from flask_sqlalchemy import SQLAlchemy from sqlalchemy.dialects.postgresql import JSONB from sqlalchemy.ext.mutable import MutableList

from werkzeug.security import generate_password_hash, check_password_hash

JWT

import jwt from jwt import ExpiredSignatureError, InvalidTokenError

Rate limiting

from flask_limiter import Limiter from flask_limiter.util import get_remote_address

#==============================

#App & Security Configuration

#==============================

app = Flask(name)

#--- Secrets & Config from ENV ---

IMPORTANT: Set these in Render dashboard -> Environment

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-this-in-render") DATABASE_URL = os.getenv("DATABASE_URL")  # e.g., Render Postgres internal URL if not DATABASE_URL: # Fallback ONLY for local dev; never commit real creds DATABASE_URL = "postgresql://user:pass@localhost:5432/testdb"

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

Cookies (even if you don't use Flask sessions, set secure defaults)

app.config["SESSION_COOKIE_HTTPONLY"] = True app.config["SESSION_COOKIE_SECURE"] = True  # requires HTTPS (enabled on Render) app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

Limit request size (protects from oversized payload DoS)

app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1MB

JWT settings

JWT_ISSUER = os.getenv("JWT_ISSUER", "your-chat-app") JWT_TTL_MINUTES = int(os.getenv("JWT_TTL_MINUTES", "10080"))  # default 7 days JWT_ALG = "HS256"

CORS — LOCK THIS DOWN

allowed_origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()] if allowed_origins: cors = CORS(app, resources={r"/*": {"origins": allowed_origins}}, supports_credentials=False) else: # Temporary open CORS for development; set ALLOWED_ORIGINS in prod cors = CORS(app)

Rate Limiter (memory storage by default; for multi-instance use Redis)

limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["2000 per day", "300 per hour"])  # general cap

DB init

db = SQLAlchemy(app)

#==============================

#Database Models

#==============================

class User(db.Model): id = db.Column(db.String, primary_key=True)  # username name = db.Column(db.String, nullable=True) password = db.Column(db.String, nullable=False)  # hashed # Deprecated: old token column (kept for backward compat, not used) token = db.Column(db.String, unique=True, nullable=True) groups = db.Column(MutableList.as_mutable(JSONB), default=list)

class Group(db.Model): id = db.Column(db.String, primary_key=True)  # group number/code name = db.Column(db.String, nullable=False) admin = db.Column(db.String, nullable=False)  # username of admin members = db.Column(MutableList.as_mutable(JSONB), default=list) messages = db.Column(MutableList.as_mutable(JSONB), default=list) edit_count = db.Column(db.Integer, default=0)

#==============================

#Utility & Security Helpers

#==============================

USERNAME_RE = re.compile(r"^[A-Za-z0-9_-.]{3,32}$")

def validate_username(u: str) -> bool: return bool(u and USERNAME_RE.match(u))

def validate_group_number(g: str) -> bool: return bool(g and re.fullmatch(r"[A-Za-z0-9_-]{3,32}", g))

def validate_name(n: str) -> bool: return bool(n and 1 <= len(n) <= 50)

def validate_message(m: str) -> bool: return bool(m and 1 <= len(m) <= 2000)

def get_india_time_iso() -> str: ist = timezone(timedelta(hours=5, minutes=30)) return datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S")

#--- JWT helpers ---

def make_jwt(sub: str) -> str: now = datetime.utcnow() payload = { "sub": sub, "iat": now, "exp": now + timedelta(minutes=JWT_TTL_MINUTES), "jti": str(uuid.uuid4()), "iss": JWT_ISSUER, } return jwt.encode(payload, app.config["SECRET_KEY"], algorithm=JWT_ALG)

def read_bearer_token() -> str | None: # Prefer Authorization: Bearer <token> auth = request.headers.get("Authorization", "") if auth.startswith("Bearer "): return auth.split(" ", 1)[1].strip() # Fallback: JSON body field "token" for backward compatibility if request.is_json: data = request.get_json(silent=True) or {} return data.get("token") return None

def authenticate() -> str | None: token = read_bearer_token() if not token: return None try: payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=[JWT_ALG], issuer=JWT_ISSUER) return payload.get("sub") except ExpiredSignatureError: return None except InvalidTokenError: return None

#==============================

Security Headers (HSTS, CSP...)

#==============================

@app.after_request def add_security_headers(resp): # Force HTTPS on browsers resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload" # Basic protections resp.headers["X-Content-Type-Options"] = "nosniff" resp.headers["X-Frame-Options"] = "DENY" resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin" # Minimal CSP (adjust if you serve inline scripts/fonts) resp.headers["Content-Security-Policy"] = ( "default-src 'self'; " "img-src 'self' data:; " "style-src 'self' 'unsafe-inline'; " "script-src 'self'; " "connect-src 'self'"  # allow API/XHR from same origin ) # Limit browser features resp.headers["Permissions-Policy"] = ( "camera=(), microphone=(), geolocation=(), usb=(), payment=()" ) # Caching for APIs resp.headers["Cache-Control"] = "no-store" return resp

#==============================

#Routes

#==============================

@app.get("/") @limiter.limit("60/minute") def index(): return "The secure server is running!", 200

@app.post("/signup") @limiter.limit("10/minute") def signup(): data = request.get_json() or {} username = (data.get("username") or "").strip() password = data.get("password") or "" name = (data.get("name") or "").strip()

if not (validate_username(username) and validate_name(name)):
    return jsonify({"success": False, "message": "Invalid username or name."}), 400

if not password or len(password) < 8:
    return jsonify({"success": False, "message": "Password must be at least 8 characters."}), 400

if User.query.get(username):
    return jsonify({"success": False, "message": "User already exists!"}), 400

hashed_password = generate_password_hash(password)
new_user = User(id=username, password=hashed_password, name=name, groups=[])
db.session.add(new_user)
db.session.commit()
return jsonify({"success": True, "message": "User created!"}), 201

@app.post("/login") @limiter.limit("5/minute")  # slow brute-force def login(): data = request.get_json() or {} username = (data.get("username") or "").strip() password = data.get("password") or ""

user = User.query.get(username)
if not user or not check_password_hash(user.password, password):
    return jsonify({"success": False, "message": "Invalid credentials!"}), 401

token = make_jwt(username)
# For backward compatibility we don't store tokens in DB; JWT is stateless
return jsonify({"success": True, "token": token, "expires_in_minutes": JWT_TTL_MINUTES}), 200

@app.post("/profile") @limiter.limit("120/minute") def profile(): user_id = authenticate() if not user_id: return jsonify({"success": False, "message": "Unauthorized!"}), 401

user_obj = User.query.get(user_id)
if not user_obj:
    return jsonify({"success": False, "message": "User not found!"}), 404

user_groups = []
for group_number in user_obj.groups or []:
    group = Group.query.get(group_number)
    if group:
        user_groups.append({
            "name": group.name,
            "number": group.id,
            "admin": group.admin
        })

return jsonify({
    "success": True,
    "name": user_obj.name,
    "groups": user_groups
}), 200

@app.post("/update_profile") @limiter.limit("30/minute") def update_profile(): user_id = authenticate() if not user_id: return jsonify({"success": False, "message": "Unauthorized!"}), 401

data = request.get_json() or {}
new_name = (data.get("newName") or "").strip()
if not validate_name(new_name):
    return jsonify({"success": False, "message": "Invalid name."}), 400

user_obj = User.query.get(user_id)
if not user_obj:
    return jsonify({"success": False, "message": "User not found!"}), 404

user_obj.name = new_name
db.session.commit()
return jsonify({"success": True, "message": "Profile updated successfully!"}), 200

@app.post("/create_group") @limiter.limit("30/minute") def create_group(): user_id = authenticate() if not user_id: return jsonify({"success": False, "message": "Unauthorized!"}), 401

data = request.get_json() or {}
group_name = (data.get("groupName") or "").strip()
group_number = (data.get("groupNumber") or "").strip()

if not (validate_name(group_name) and validate_group_number(group_number)):
    return jsonify({"success": False, "message": "Invalid group name or number."}), 400

if Group.query.get(group_number):
    return jsonify({"success": False, "message": "Group already exists!"}), 400

group = Group(id=group_number, name=group_name, admin=user_id, members=[user_id], messages=[])
db.session.add(group)

user_obj = User.query.get(user_id)
if group_number not in (user_obj.groups or []):
    user_obj.groups.append(group_number)
    db.session.add(user_obj)

db.session.commit()
return jsonify({"success": True, "message": f"Group {group_number} created!"}), 201

@app.post("/join_group") @limiter.limit("60/minute") def join_group(): user_id = authenticate() if not user_id: return jsonify({"success": False, "message": "Unauthorized!"}), 401

data = request.get_json() or {}
group_number = (data.get("groupNumber") or "").strip()

group = Group.query.get(group_number)
if not group:
    return jsonify({"success": False, "message": "Group not found!"}), 404

user_obj = User.query.get(user_id)

if user_id in (group.members or []):
    return jsonify({"success": False, "message": "Already a member of this group."}), 400

group.members.append(user_id)
user_obj.groups.append(group_number)

db.session.commit()
return jsonify({"success": True, "message": f"Joined group {group_number}!"}), 200

@app.post("/send_message") @limiter.limit("300/minute") def send_message(): user_id = authenticate() if not user_id: return jsonify({"success": False, "message": "Unauthorized!"}), 401

data = request.get_json() or {}
group_number = (data.get("groupNumber") or "").strip()
text = (data.get("message") or "").strip()

if not validate_message(text):
    return jsonify({"success": False, "message": "Invalid/empty message or too long."}), 400

group = Group.query.get(group_number)
if not group:
    return jsonify({"success": False, "message": "Group not found!"}), 404

if user_id not in (group.members or []):
    return jsonify({"success": False, "message": "Not a member of this group."}), 403

user_obj = User.query.get(user_id)
new_message = {
    "user": user_obj.name,
    "sender_username": user_id,
    "text": text,
    "time": get_india_time_iso(),
}

group.messages.append(new_message)
db.session.commit()
return jsonify({"success": True, "message": "Message sent!"}), 200

@app.post("/get_messages/<group_number>") @limiter.limit("120/minute") def get_messages(group_number): user_id = authenticate() if not user_id: return jsonify({"success": False, "message": "Unauthorized!"}), 401

group = Group.query.get(group_number)
if not group:
    return jsonify({"success": False, "message": "Group not found!"}), 404

if user_id not in (group.members or []):
    return jsonify({"success": False, "message": "Not a member of this group."}), 403

return jsonify({"success": True, "messages": group.messages or []}), 200

@app.post("/delete_group") @limiter.limit("20/minute") def delete_group(): user_id = authenticate() if not user_id: return jsonify({"success": False, "message": "Unauthorized!"}), 401

data = request.get_json() or {}
group_number = (data.get("groupNumber") or "").strip()

group = Group.query.get(group_number)
if not group:
    return jsonify({"success": False, "message": "Group not found!"}), 404

if group.admin != user_id:
    return jsonify({"success": False, "message": "Only the admin can delete the group."}), 403

# Remove group from all members' group lists
for member_id in list(group.members or []):
    member = User.query.get(member_id)
    if member and group_number in (member.groups or []):
        member.groups.remove(group_number)
        db.session.add(member)

db.session.delete(group)
db.session.commit()
return jsonify({"success": True, "message": "Group deleted successfully!"}), 200

@app.post("/leave_group") @limiter.limit("60/minute") def leave_group(): user_id = authenticate() if not user_id: return jsonify({"success": False, "message": "Unauthorized!"}), 401

data = request.get_json() or {}
group_number = (data.get("groupNumber") or "").strip()

group = Group.query.get(group_number)
if not group:
    return jsonify({"success": False, "message": "Group not found!"}), 404

if user_id not in (group.members or []):
    return jsonify({"success": False, "message": "You are not a member of this group."}), 400

if group.admin == user_id:
    return jsonify({"success": False, "message": "Admin cannot leave the group. Please delete it instead."}), 400

user_obj = User.query.get(user_id)

group.members.remove(user_id)
if group_number in (user_obj.groups or []):
    user_obj.groups.remove(group_number)

db.session.commit()
return jsonify({"success": True, "message": "You have left the group."}), 200

@app.post("/update_group_name") @limiter.limit("20/minute") def update_group_name(): user_id = authenticate() if not user_id: return jsonify({"success": False, "message": "Unauthorized!"}), 401

data = request.get_json() or {}
group_number = (data.get("groupNumber") or "").strip()
new_group_name = (data.get("newGroupName") or "").strip()

if not validate_name(new_group_name):
    return jsonify({"success": False, "message": "Invalid group name."}), 400

group = Group.query.get(group_number)
if not group:
    return jsonify({"success": False, "message": "Group not found!"}), 404

if group.admin != user_id:
    return jsonify({"success": False, "message": "Only the admin can edit the group name."}), 403

if (group.edit_count or 0) >= 2:
    return jsonify({"success": False, "message": "Group name can only be edited twice."}), 403

group.name = new_group_name
group.edit_count = (group.edit_count or 0) + 1
db.session.commit()
return jsonify({"success": True, "message": "Group name updated successfully!"}), 200

#==============================

#DB Init

#==============================

with app.app_context(): db.create_all()

#==============================

Entrypoint (Production-safe)

==============================

if name == "main": # Never enable debug in production port = int(os.getenv("PORT", "5000")) app.run(host="0.0.0.0", port=port, debug=False)

