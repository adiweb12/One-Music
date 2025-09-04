from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime

app = Flask(__name__)

# --- CONFIG ---
app.config['SECRET_KEY'] = "supersecretkey"  # Change in production
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://testbase_uxax_user:3GRVXgVpQvcuuCtLTEWnBes5NFx5D6Ry@dpg-d2sg9c3e5dus73el8pvg-a/testbase_uxax"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100), nullable=False)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    number = db.Column(db.String(50), unique=True, nullable=False)

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"))
    sender = db.Column(db.String(100))
    message = db.Column(db.Text)
    time = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# --- HELPERS ---
def generate_token(username):
    return jwt.encode(
        {"username": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)},
        app.config['SECRET_KEY'],
        algorithm="HS256"
    )

def verify_token(token):
    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return decoded['username']
    except:
        return None

# --- ROUTES ---
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    name = data.get("name")

    if User.query.filter_by(username=username).first():
        return jsonify({"success": False, "message": "Username already exists"})

    hashed_pw = generate_password_hash(password)
    new_user = User(username=username, password=hashed_pw, name=name)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"success": True, "message": "Signup successful"})

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"success": False, "message": "Invalid username or password"})

    token = generate_token(username)
    return jsonify({"success": True, "token": token})

@app.route("/profile", methods=["POST"])
def profile():
    data = request.get_json()
    token = data.get("token")
    username = verify_token(token)
    if not username:
        return jsonify({"success": False, "message": "Invalid token"})

    user = User.query.filter_by(username=username).first()
    memberships = GroupMember.query.filter_by(user_id=user.id).all()
    groups = []
    for m in memberships:
        g = Group.query.get(m.group_id)
        groups.append({"name": g.name, "number": g.number})

    return jsonify({"success": True, "name": user.name, "groups": groups})

@app.route("/update_profile", methods=["POST"])
def update_profile():
    data = request.get_json()
    token = data.get("token")
    new_name = data.get("newName")
    username = verify_token(token)
    if not username:
        return jsonify({"success": False, "message": "Invalid token"})

    user = User.query.filter_by(username=username).first()
    user.name = new_name
    db.session.commit()

    return jsonify({"success": True, "message": "Profile updated"})

@app.route("/create_group", methods=["POST"])
def create_group():
    data = request.get_json()
    token = data.get("token")
    username = verify_token(token)
    if not username:
        return jsonify({"success": False, "message": "Invalid token"})

    group_name = data.get("groupName")
    group_number = data.get("groupNumber")

    if Group.query.filter_by(number=group_number).first():
        return jsonify({"success": False, "message": "Group number already exists"})

    user = User.query.filter_by(username=username).first()
    group = Group(name=group_name, number=group_number)
    db.session.add(group)
    db.session.commit()

    membership = GroupMember(group_id=group.id, user_id=user.id)
    db.session.add(membership)
    db.session.commit()

    return jsonify({"success": True, "message": "Group created successfully"})

@app.route("/join_group", methods=["POST"])
def join_group():
    data = request.get_json()
    token = data.get("token")
    username = verify_token(token)
    if not username:
        return jsonify({"success": False, "message": "Invalid token"})

    group_number = data.get("groupNumber")
    group = Group.query.filter_by(number=group_number).first()
    if not group:
        return jsonify({"success": False, "message": "Group not found"})

    user = User.query.filter_by(username=username).first()
    if GroupMember.query.filter_by(group_id=group.id, user_id=user.id).first():
        return jsonify({"success": False, "message": "Already joined"})

    membership = GroupMember(group_id=group.id, user_id=user.id)
    db.session.add(membership)
    db.session.commit()

    return jsonify({"success": True, "message": "Joined successfully"})

@app.route("/send_message", methods=["POST"])
def send_message():
    data = request.get_json()
    token = data.get("token")
    username = verify_token(token)
    if not username:
        return jsonify({"success": False, "message": "Invalid token"})

    group_number = data.get("groupNumber")
    message_text = data.get("message")
    group = Group.query.filter_by(number=group_number).first()
    if not group:
        return jsonify({"success": False, "message": "Group not found"})

    msg = Message(group_id=group.id, sender=username, message=message_text)
    db.session.add(msg)
    db.session.commit()

    return jsonify({"success": True, "message": "Message sent"})

@app.route("/get_messages/<group_number>", methods=["POST"])
def get_messages(group_number):
    data = request.get_json()
    token = data.get("token")
    username = verify_token(token)
    if not username:
        return jsonify({"success": False, "message": "Invalid token"})

    group = Group.query.filter_by(number=group_number).first()
    if not group:
        return jsonify({"success": False, "message": "Group not found"})

    msgs = Message.query.filter_by(group_id=group.id).order_by(Message.time.asc()).all()
    messages = [{"sender": m.sender, "message": m.message, "time": m.time.isoformat()} for m in msgs]

    return jsonify({"success": True, "messages": messages})

# --- MAIN ---
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=5000)
