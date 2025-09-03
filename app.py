from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime, timedelta, timezone
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

# ==============================
# Database Configuration
# ==============================

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://testbase_00su_user:umk115OrLKubuKjvaqolOaFfpfOQxSiI@dpg-d2s23oemcj7s73fp22b0-a/testbase_00su"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ==============================
# Database Models
# ==============================

class User(db.Model):
    id = db.Column(db.String, primary_key=True)
    name = db.Column(db.String, nullable=True)
    password = db.Column(db.String, nullable=False)
    token = db.Column(db.String, unique=True, nullable=True)
    groups = db.Column(JSONB, default=list)

class Group(db.Model):
    id = db.Column(db.String, primary_key=True)
    name = db.Column(db.String, nullable=False)
    admin = db.Column(db.String, nullable=False)
    members = db.Column(JSONB, default=list)
    messages = db.Column(JSONB, default=list)
    edit_count = db.Column(db.Integer, default=0)

# ==============================
# Helper Functions
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

# Added a new route for the root URL
@app.route("/")
def index():
    return "The server is running!", 200

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    name = data.get("name")

    if not username or not password or not name:
        return jsonify({"success": False, "message": "Username, password, and name are required."}), 400

    if User.query.get(username):
        return jsonify({"success": False, "message": "User already exists!"}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(id=username, password=hashed_password, name=name, groups=[])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"success": True, "message": "User created!"})

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = User.query.get(username)
    if not user or not check_password_hash(user.password, password):
        return jsonify({"success": False, "message": "Invalid credentials!"}), 401

    user.token = str(uuid.uuid4())
    db.session.commit()
    return jsonify({"success": True, "token": user.token})

@app.route("/profile", methods=["POST"])
def profile():
    data = request.get_json()
    token = data.get("token")
    user_id = authenticate(token)
    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401
    
    user_obj = User.query.get(user_id)
    user_groups = []
    for group_number in user_obj.groups:
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

@app.route("/update_profile", methods=["POST"])
def update_profile():
    data = request.get_json()
    token = data.get("token")
    new_name = data.get("newName")
    user_id = authenticate(token)
    
    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401
    
    user_obj = User.query.get(user_id)
    user_obj.name = new_name
    db.session.commit()
    return jsonify({"success": True, "message": "Profile updated successfully!"}), 200

@app.route("/create_group", methods=["POST"])
def create_group():
    data = request.get_json()
    token = data.get("token")
    group_name = data.get("groupName")
    group_number = data.get("groupNumber")
    user_id = authenticate(token)

    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401
    
    if not group_name or not group_number:
        return jsonify({"success": False, "message": "Group name and number are required."}), 400

    if Group.query.get(group_number):
        return jsonify({"success": False, "message": "Group already exists!"}), 400

    group = Group(id=group_number, name=group_name, admin=user_id, members=[user_id], messages=[])
    db.session.add(group)

    user_obj = User.query.get(user_id)
    if group_number not in user_obj.groups:
        user_obj.groups.append(group_number)
    
    db.session.commit()
    return jsonify({"success": True, "message": f"Group {group_number} created!"})

@app.route("/join_group", methods=["POST"])
def join_group():
    data = request.get_json()
    token = data.get("token")
    group_number = data.get("groupNumber")
    user_id = authenticate(token)

    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401
    
    group = Group.query.get(group_number)
    if not group:
        return jsonify({"success": False, "message": "Group not found!"}), 404
    
    user_obj = User.query.get(user_id)
    if user_id in group.members:
        return jsonify({"success": False, "message": "Already a member of this group."}), 400
    
    group.members.append(user_id)
    user_obj.groups.append(group_number)
    
    db.session.commit()
    return jsonify({"success": True, "message": f"Joined group {group_number}!"})

@app.route("/send_message", methods=["POST"])
def send_message():
    data = request.get_json()
    token = data.get("token")
    group_number = data.get("groupNumber")
    text = data.get("message")
    user_id = authenticate(token)

    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401
    
    group = Group.query.get(group_number)
    if not group:
        return jsonify({"success": False, "message": "Group not found!"}), 404
    
    if user_id not in group.members:
        return jsonify({"success": False, "message": "Not a member of this group."}), 403

    user_obj = User.query.get(user_id)
    
    new_message = {
        "user": user_obj.name,
        "sender_username": user_id,
        "text": text,
        "time": get_india_time()
    }
    
    group.messages.append(new_message)
    db.session.commit()
    return jsonify({"success": True, "message": "Message sent!"})

@app.route("/get_messages/<group_number>", methods=["POST"])
def get_messages(group_number):
    data = request.get_json()
    token = data.get("token")
    user_id = authenticate(token)

    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401

    group = Group.query.get(group_number)
    if not group:
        return jsonify({"success": False, "message": "Group not found!"}), 404

    if user_id not in group.members:
        return jsonify({"success": False, "message": "Not a member of this group."}), 403

    return jsonify({"success": True, "messages": group.messages}), 200

@app.route("/delete_group", methods=["POST"])
def delete_group():
    data = request.get_json()
    token = data.get("token")
    group_number = data.get("groupNumber")
    user_id = authenticate(token)
    
    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401
    
    group = Group.query.get(group_number)
    if not group:
        return jsonify({"success": False, "message": "Group not found!"}), 404
    
    if group.admin != user_id:
        return jsonify({"success": False, "message": "Only the admin can delete the group."}), 403
    
    # Remove group from all members' group lists
    for member_id in group.members:
        member = User.query.get(member_id)
        if member:
            if group_number in member.groups:
                member.groups.remove(group_number)
    
    db.session.delete(group)
    db.session.commit()
    return jsonify({"success": True, "message": "Group deleted successfully!"}), 200

@app.route("/leave_group", methods=["POST"])
def leave_group():
    data = request.get_json()
    token = data.get("token")
    group_number = data.get("groupNumber")
    user_id = authenticate(token)

    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401
    
    group = Group.query.get(group_number)
    if not group:
        return jsonify({"success": False, "message": "Group not found!"}), 404
    
    if user_id not in group.members:
        return jsonify({"success": False, "message": "You are not a member of this group."}), 400
    
    if group.admin == user_id:
        return jsonify({"success": False, "message": "Admin cannot leave the group. Please delete it instead."}), 400

    user_obj = User.query.get(user_id)
    group.members.remove(user_id)
    user_obj.groups.remove(group_number)
    db.session.commit()
    return jsonify({"success": True, "message": "You have left the group."}), 200

@app.route("/update_group_name", methods=["POST"])
def update_group_name():
    data = request.get_json()
    token = data.get("token")
    group_number = data.get("groupNumber")
    new_group_name = data.get("newGroupName")
    user_id = authenticate(token)
    
    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401
    
    group = Group.query.get(group_number)
    if not group:
        return jsonify({"success": False, "message": "Group not found!"}), 404
    
    if group.admin != user_id:
        return jsonify({"success": False, "message": "Only the admin can edit the group name."}), 403
    
    if group.edit_count >= 2:
        return jsonify({"success": False, "message": "Group name can only be edited twice."}), 403

    group.name = new_group_name
    group.edit_count += 1
    db.session.commit()
    return jsonify({"success": True, "message": "Group name updated successfully!"}), 200

# ==============================
# Initialize Database
# ==============================

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
