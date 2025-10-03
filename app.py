# app.py

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import threading
import time
import uuid
import os
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSONB
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from sqlalchemy import event, DDL

# -------------------- LOGGING SETUP --------------------
# Set up basic logging to see errors in the console
logging.basicConfig(level=logging.INFO)

# -------------------- APP & DB SETUP --------------------
app = Flask(__name__)
CORS(app)

# NOTE: Replace with your actual connection string if deploying
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'postgresql://onechat_nhc9_user:JoXwS5h0cfjKLYVV0XMeaXsqhgWBKxjm@dpg-d3efbpggjchc738litc0-a/onechat_nhc9'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# -------------------- DATABASE MODELS --------------------
class User(db.Model):
    __tablename__ = 'users'
    username = db.Column(db.String(50), primary_key=True)
    password = db.Column(db.String(200), nullable=False)  # hashed
    name = db.Column(db.String(100), nullable=False)
    groups = db.Column(JSONB, default=list)

class Group(db.Model):
    __tablename__ = 'groups'
    group_number = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    members = db.Column(JSONB, default=list)
    creator = db.Column(db.String(50), db.ForeignKey('users.username'), nullable=False) 

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    group_number = db.Column(db.String(50), db.ForeignKey('groups.group_number'), nullable=False)
    sender = db.Column(db.String(50), db.ForeignKey('users.username'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    # ⚠️ IMPORTANT: time is stored as UTC and used for sync filtering
    time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow) 

class Session(db.Model):
    __tablename__ = 'sessions'
    username = db.Column(db.String(50), primary_key=True, unique=True)
    token = db.Column(db.String(200), nullable=False)

# -------------------- INDEX CREATION (for performance) --------------------
# This ensures that querying messages by group_number and time is fast
# which is essential for the new sync logic.
index_ddl = DDL('CREATE INDEX idx_messages_group_time ON messages (group_number, time)')
event.listen(Message.__table__, 'after_create', index_ddl.execute_if(dialect='postgresql'))


# -------------------- AUTH HELPERS --------------------
def generate_token():
    return str(uuid.uuid4())

def authenticate(token):
    if not token:
        return None
    session = Session.query.filter_by(token=token).first()
    return session.username if session else None

# -------------------- DATABASE CREATION --------------------
with app.app_context():
    # This will create tables if they don't exist
    db.create_all() 

# -------------------- ROOT --------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "success": True,
        "message": "🚀 OneChat API is running! Database connection active."
    })

# -------------------- SIGNUP --------------------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    name = data.get("name", username)

    if not username or not password or not name:
        return jsonify({"success": False, "message": "Missing fields!"}), 400
    
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters long."}), 400

    if User.query.get(username):
        return jsonify({"success": False, "message": "Username already exists!"}), 400

    hashed = generate_password_hash(password)
    new_user = User(username=username, password=hashed, name=name, groups=[])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"success": True, "message": "Signup successful!"})

# -------------------- LOGIN --------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"success": False, "message": "Missing fields!"}), 400

    user = User.query.get(username)
    if user and check_password_hash(user.password, password):
        token = generate_token()
        session = Session.query.get(username)
        if session:
            session.token = token
        else:
            new_session = Session(username=username, token=token)
            db.session.add(new_session)
        db.session.commit()
        return jsonify({"success": True, "message": "Login successful!", "token": token})
    else:
        return jsonify({"success": False, "message": "Invalid credentials!"}), 401

# -------------------- LOGOUT --------------------
@app.route("/logout", methods=["POST"])
def logout():
    data = request.get_json() or {}
    token = data.get("token")
    if not token:
        return jsonify({"success": False, "message": "Missing token!"}), 400

    session = Session.query.filter_by(token=token).first()
    if not session:
        return jsonify({"success": False, "message": "Invalid token!"}), 401

    db.session.delete(session)
    db.session.commit()
    return jsonify({"success": True, "message": "Logout successful!"})

# -------------------- CREATE GROUP --------------------
@app.route("/create_group", methods=["POST"])
def create_group():
    data = request.get_json() or {}
    token = data.get("token")
    group_name = data.get("groupName")
    group_number = data.get("groupNumber")

    user = authenticate(token)
    if not user:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401

    if not group_name or not group_number:
        return jsonify({"success": False, "message": "Missing fields!"}), 400

    if Group.query.get(group_number):
        return jsonify({"success": False, "message": "Group number already exists!"}), 400

    new_group = Group(group_number=group_number, name=group_name, members=[user], creator=user)
    db.session.add(new_group)

    user_obj = User.query.get(user)
    if user_obj and group_number not in (user_obj.groups or []):
        user_obj.groups = (user_obj.groups or []) + [group_number]

    db.session.commit()
    return jsonify({"success": True, "message": f"Group '{group_name}' created successfully!"})

# -------------------- JOIN GROUP --------------------
@app.route("/join_group", methods=["POST"])
def join_group():
    data = request.get_json() or {}
    token = data.get("token")
    group_number = data.get("groupNumber")

    user = authenticate(token)
    if not user:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401

    if not group_number:
        return jsonify({"success": False, "message": "Missing group number!"}), 400

    group = Group.query.get(group_number)
    if not group:
        return jsonify({"success": False, "message": "Group not found!"}), 404

    if user not in (group.members or []):
        group.members = (group.members or []) + [user]

    user_obj = User.query.get(user)
    if user_obj and group_number not in (user_obj.groups or []):
        user_obj.groups = (user_obj.groups or []) + [group_number]

    db.session.commit()
    return jsonify({"success": True, "message": f"Joined group '{group.name}' successfully!"})

# -------------------- LEAVE GROUP --------------------
@app.route("/leave_group", methods=["POST"])
def leave_group():
    data = request.get_json() or {}
    token = data.get("token")
    group_number = data.get("groupNumber")

    user = authenticate(token)
    if not user:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401

    group = Group.query.get(group_number)
    user_obj = User.query.get(user)

    if not group or not user_obj:
        return jsonify({"success": False, "message": "Group or User not found!"}), 404

    # Remove user from group members
    if user in (group.members or []):
        group.members.remove(user)

    # Remove group from user's groups list
    if group_number in (user_obj.groups or []):
        user_obj.groups.remove(group_number)

    # Check if the user was the creator and if the group is now empty
    if group.creator == user:
        if not group.members:
            # If creator leaves and no one is left, delete the group
            Message.query.filter_by(group_number=group_number).delete()
            db.session.delete(group)
            db.session.commit()
            return jsonify({"success": True, "message": "Group left and deleted (group was empty)!"})
        else:
            # If creator leaves and others are left, assign a new creator
            group.creator = group.members[0] # Assign first member as new creator
            db.session.commit()
            return jsonify({"success": True, "message": f"Group left. New admin: {group.creator}"})
    else:
        db.session.commit()
        return jsonify({"success": True, "message": "Group left successfully!"})

# -------------------- DELETE GROUP --------------------
@app.route("/delete_group", methods=["POST"])
def delete_group():
    data = request.get_json() or {}
    token = data.get("token")
    group_number = data.get("groupNumber")

    user = authenticate(token)
    if not user:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401

    group = Group.query.get(group_number)
    if not group:
        return jsonify({"success": False, "message": "Group not found!"}), 404

    # Authorization Check: Only the creator can delete the group
    if group.creator != user:
        return jsonify({"success": False, "message": "Only the group admin can delete the group!"}), 403

    # Remove group from all members' group lists
    for member_username in (group.members or []):
        member = User.query.get(member_username)
        if member and group_number in (member.groups or []):
            member.groups.remove(group_number)

    # Delete all messages in the group
    Message.query.filter_by(group_number=group_number).delete()

    # Delete the group itself
    db.session.delete(group)
    db.session.commit()
    return jsonify({"success": True, "message": f"Group '{group.name}' and all messages deleted successfully!"})


# -------------------- GET PROFILE --------------------
@app.route("/profile", methods=["POST"])
def get_profile():
    data = request.get_json() or {}
    token = data.get("token")

    user = authenticate(token)
    if not user:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401

    user_obj = User.query.get(user)
    user_groups = []
    if user_obj:
        for gnum in (user_obj.groups or []):
            grp = Group.query.get(gnum)
            if grp:
                is_creator = grp.creator == user
                user_groups.append({"name": grp.name, "number": gnum, "is_creator": is_creator})

    return jsonify({
        "success": True,
        "username": user,
        "name": user_obj.name if user_obj else "",
        "groups": user_groups
    })

# -------------------- UPDATE PROFILE --------------------
@app.route("/update_profile", methods=["POST"])
def update_profile():
    data = request.get_json() or {}
    token = data.get("token")
    new_name = data.get("newName")

    user = authenticate(token)
    if not user:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401

    user_obj = User.query.get(user)
    if user_obj:
        user_obj.name = new_name or user_obj.name
        db.session.commit()

    return jsonify({"success": True, "message": "Profile updated successfully!"})

# -------------------- SEND MESSAGE --------------------
@app.route("/send_message", methods=["POST"])
def send_message():
    data = request.get_json() or {}
    token = data.get("token")
    group_number = data.get("groupNumber")
    text = data.get("message")

    user = authenticate(token)
    if not user:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401

    if not Group.query.get(group_number):
        return jsonify({"success": False, "message": "Group not found!"}), 404
    
    if not text:
        return jsonify({"success": False, "message": "Message cannot be empty!"}), 400


    new_message = Message(
        sender=user,
        message=text,
        group_number=group_number,
        time=datetime.utcnow() # Use UTC for consistent syncing
    )
    db.session.add(new_message)
    db.session.commit()
    # Return the exact server-generated time for better client sync confirmation
    return jsonify({
        "success": True, 
        "message": "Message sent!",
        "time": new_message.time.isoformat()
    })

# -------------------- GET MESSAGES (SYNC ENDPOINT) --------------------
@app.route("/get_messages/<group_number>", methods=["POST"])
def get_messages(group_number):
    data = request.get_json() or {}
    token = data.get("token")
    # 🌟 NEW: Retrieve the optional last_synced_time from the client
    last_synced_time = data.get("last_synced_time") 

    user = authenticate(token)
    if not user:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401
    
    # Base query: filter by group number
    query = Message.query.filter_by(group_number=group_number)
    
    # 🌟 IMPLEMENT INCREMENTAL SYNC
    if last_synced_time:
        try:
            # Parse the ISO 8601 string received from the client
            last_time = datetime.fromisoformat(last_synced_time.replace('Z', '+00:00'))
            
            # Filter messages where the server time is strictly GREATER than the client's last time
            # This is the core of the incremental sync.
            query = query.filter(Message.time > last_time)
            
            app.logger.info(f"Syncing group {group_number} for {user} since {last_synced_time}")
            
        except ValueError:
            # If the timestamp is invalid, log it and proceed to return ALL messages (or just the latest)
            app.logger.warning(f"Invalid last_synced_time received: {last_synced_time}. Returning all messages.")
            # We proceed with the base query (all messages) if the time filter fails
            

    # Apply ordering and execute
    # Note: If last_synced_time was valid, this only returns NEW messages.
    # If not, it returns all messages for the group (acting as a full refresh).
    group_messages = query.order_by(Message.time.asc()).all()

    return jsonify({
        "success": True,
        "messages": [
            {"sender": m.sender, "message": m.message, "time": m.time.isoformat()}
            for m in group_messages
        ]
    })

# -------------------- MESSAGE CLEANUP --------------------
def cleanup_messages():
    with app.app_context():
        # Set a slightly longer retention policy to ensure messages are available for sync
        # The client side uses a timer, so 24 hours is quite short for a chat app.
        # Let's keep it at 7 days (168 hours) for this example.
        RETENTION_HOURS = 168 # 7 days
        
        while True:
            try:
                now = datetime.utcnow()
                cutoff_time = now - timedelta(hours=RETENTION_HOURS)
                
                # Ensure only messages older than the cutoff are deleted
                deleted_count = Message.query.filter(Message.time < cutoff_time).delete(synchronize_session='fetch')
                db.session.commit()
                app.logger.info(f"Cleanup thread: Deleted {deleted_count} messages older than {RETENTION_HOURS} hours.")
            except Exception as e:
                app.logger.exception("Cleanup thread error: %s", e)
                db.session.rollback()
            time.sleep(3600 * 6)  # Run cleanup every 6 hours

threading.Thread(target=cleanup_messages, daemon=True).start()

# -------------------- RUN SERVER --------------------
if __name__ == "__main__":
    # Check if a specific PORT is set in environment variables, default to 5000
    port = int(os.environ.get("PORT", 5000)) 
    # Note: Set debug=False in production
    app.run(host="0.0.0.0", port=port, debug=True)
