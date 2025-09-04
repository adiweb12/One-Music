from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room

app = Flask(__name__)
CORS(app)

# Database (SQLite, can change to PostgreSQL/MySQL)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///chat.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

socketio = SocketIO(app, cors_allowed_origins="*")

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)


# --- Routes ---
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"error": "Username already exists"}), 400
    
    hashed_pw = generate_password_hash(data["password"])
    new_user = User(username=data["username"], password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully!"})


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    user = User.query.filter_by(username=data["username"]).first()
    if not user or not check_password_hash(user.password, data["password"]):
        return jsonify({"error": "Invalid credentials"}), 401
    
    return jsonify({"message": "Login successful!", "username": user.username})


# --- WebSocket Events ---
@socketio.on("create_room")
def create_room(data):
    room = data["room"]
    username = data["username"]

    if not Room.query.filter_by(name=room).first():
        new_room = Room(name=room)
        db.session.add(new_room)
        db.session.commit()

    join_room(room)
    emit("room_created", {"room": room, "username": username}, room=room)


@socketio.on("join_room")
def join_existing_room(data):
    room = data["room"]
    username = data["username"]

    if not Room.query.filter_by(name=room).first():
        emit("error", {"message": "Room does not exist"})
        return

    join_room(room)
    emit("room_joined", {"room": room, "username": username}, room=room)


@socketio.on("send_message")
def handle_message(data):
    room = data["room"]
    print(f"[{room}] {data['username']}: {data['message']}")
    emit("receive_message", data, room=room)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
