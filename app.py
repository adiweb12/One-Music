from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime, timedelta, timezone
import uuid

app = Flask(__name__)
CORS(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///chat.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


# ==============================
# Database Models
# ==============================
class User(db.Model):
    id = db.Column(db.String, primary_key=True)
    password = db.Column(db.String, nullable=False)
    token = db.Column(db.String, unique=True, nullable=True)
    groups = db.Column(JSONB, default=list)  # List of group numbers


class Group(db.Model):
    id = db.Column(db.String, primary_key=True)
    members = db.Column(JSONB, default=list)  # List of usernames
    messages = db.Column(JSONB, default=list)  # Each message: {"user":..., "text":..., "time":...}


# ==============================
# Helpers
# ==============================
def authenticate(token):
    """Find user by token"""
    if not token:
        return None
    user = User.query.filter_by(token=token).first()
    return user.id if user else None


def get_india_time():
    """Return current time in IST as ISO string"""
    ist = timezone(timedelta(hours=5, minutes=30))
    return datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S")


# ==============================
# API Routes
# ==============================
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if User.query.get(username):
        return jsonify({"success": False, "message": "User already exists!"}), 400

    new_user = User(id=username, password=password, groups=[])
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"success": True, "message": "User created!"})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = User.query.get(username)
    if not user or user.password != password:
        return jsonify({"success": False, "message": "Invalid credentials!"}), 401

    user.token = str(uuid.uuid4())
    db.session.commit()

    return jsonify({"success": True, "token": user.token})


@app.route("/create_group", methods=["POST"])
def create_group():
    data = request.get_json()
    token = data.get("token")
    group_number = data.get("group_number")

    user = authenticate(token)
    if not user:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401

    if Group.query.get(group_number):
        return jsonify({"success": False, "message": "Group already exists!"}), 400

    group = Group(id=group_number, members=[user], messages=[])
    db.session.add(group)

    user_obj = User.query.get(user)
    if group_number not in user_obj.groups:
        user_obj.groups = user_obj.groups + [group_number]

    db.session.commit()
    return jsonify({"success": True, "message": f"Group {group_number} created!"})


@app.route("/join_group", methods=["POST"])
def join_group():
    data = request.get_json()
    token = data.get("token")
    group_number = data.get("group_number")

    user = authenticate(token)
    if not user:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401

    group = Group.query.get(group_number)
    if not group:
        return jsonify({"success": False, "message": "Group not found!"}), 404

    if user not in group.members:
        group.members = group.members + [user]

    user_obj = User.query.get(user)
    if group_number not in user_obj.groups:
        user_obj.groups = user_obj.groups + [group_number]

    db.session.commit()
    return jsonify({"success": True, "message": f"Joined group {group_number}!"})


@app.route("/send_message", methods=["POST"])
def send_message():
    data = request.get_json()
    token = data.get("token")
    group_number = data.get("group_number")
    text = data.get("text")

    user = authenticate(token)
    if not user:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401

    group = Group.query.get(group_number)
    if not group:
        return jsonify({"success": False, "message": "Group not found!"}), 404

    if user not in group.members:
        return jsonify({"success": False, "message": "Not a member of this group."}), 403

    # Add message with IST timestamp
    group.messages = group.messages + [{
        "user": user,
        "text": text,
        "time": get_india_time()
    }]
    db.session.commit()

    return jsonify({"success": True, "message": "Message sent!"})


@app.route("/get_messages/<group_number>", methods=["POST"])
def get_messages(group_number):
    data = request.get_json()
    token = data.get("token")

    user = authenticate(token)
    if not user:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401

    group = Group.query.get(group_number)
    if not group:
        return jsonify({"success": False, "message": "Group not found!"}), 404

    if user not in group.members:
        return jsonify({"success": False, "message": "Not a member of this group."}), 403

    return jsonify({"success": True, "messages": group.messages})


# ==============================
# Init DB
# ==============================
with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
