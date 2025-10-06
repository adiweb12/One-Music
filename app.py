# app.py
import os
from datetime import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, join_room, emit
from werkzeug.security import generate_password_hash, check_password_hash
import logging

# ------------------------------------------------------------
# Flask Configuration
# ------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "supersecret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "postgresql://user:password@localhost:5432/chatdb"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# ------------------------------------------------------------
# Logging Setup
# ------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ------------------------------------------------------------
# Database Models
# ------------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, nullable=True)  # for private chat
    group_name = db.Column(db.String(50), nullable=True)  # for group chat
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------

@app.route("/")
def home():
    return jsonify({"message": "Chat App Backend Running 🚀"})


@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json() or {}
    phone = data.get("phone")
    password = data.get("password")
    username = data.get("username") or f"User_{phone[-4:]}" if phone else None

    if not phone or not password or not username:
        return jsonify({"message": "Missing phone, username or password"}), 400

    if User.query.filter_by(phone=phone).first():
        return jsonify({"message": "Phone already registered"}), 400

    hashed_password = generate_password_hash(password)
    user = User(phone=phone, username=username, password=hashed_password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Signup successful", "user": {"id": user.id, "username": user.username}}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    phone = data.get("phone")
    password = data.get("password")

    if not phone or not password:
        return jsonify({"message": "Missing phone or password"}), 400

    user = User.query.filter_by(phone=phone).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"message": "Invalid phone or password"}), 401

    return jsonify({"message": "Login successful", "user": {"id": user.id, "username": user.username}})


# ------------------------------------------------------------
# Socket.IO Events
# ------------------------------------------------------------

@socketio.on("connect")
def handle_connect():
    logger.info("A user connected ✅")
    emit("connected", {"message": "You are connected to the server"})


@socketio.on("join_chat")
def handle_join_chat(data):
    room = data.get("room")
    if room:
        join_room(room)
        emit("joined", {"room": room}, room=room)
        logger.info(f"User joined room: {room}")


@socketio.on("send_message")
def handle_send_message(data):
    sender_id = data.get("sender_id")
    receiver_id = data.get("receiver_id")
    group_name = data.get("group_name")
    content = data.get("content")

    if not sender_id or not content:
        emit("error", {"message": "Missing sender_id or content"})
        return

    msg = Message(sender_id=sender_id, receiver_id=receiver_id, group_name=group_name, content=content)
    db.session.add(msg)
    db.session.commit()

    payload = {
        "id": msg.id,
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "group_name": group_name,
        "content": content,
        "timestamp": msg.timestamp.isoformat(),
    }

    if group_name:
        emit("new_message", payload, room=group_name)
    elif receiver_id:
        private_room = f"private_{min(sender_id, receiver_id)}_{max(sender_id, receiver_id)}"
        emit("new_message", payload, room=private_room)


@socketio.on("typing")
def handle_typing(data):
    room = data.get("room")
    username = data.get("username")
    if room:
        emit("typing", {"username": username}, room=room)


# ------------------------------------------------------------
# Initialize Database
# ------------------------------------------------------------
@app.before_request
def create_tables():
    db.create_all()


# ------------------------------------------------------------
# Run App (Safe for Render)
# ------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Starting server on port {port}")
    socketio.run(app, host="0.0.0.0", port=port, allow_unsafe_werkzeug=True)
