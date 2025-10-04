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
from sqlalchemy import event, DDL, func

# -------------------- LOGGING SETUP --------------------
logging.basicConfig(level=logging.INFO)

# -------------------- APP & DB SETUP --------------------
app = Flask(__name__)
CORS(app)

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

# 🌟 NEW: Track last read time for unread count
class GroupStatus(db.Model):
    __tablename__ = 'group_status'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), db.ForeignKey('users.username'), nullable=False)
    group_number = db.Column(db.String(50), db.ForeignKey('groups.group_number'), nullable=False)
    # The time of the last message the user read
    last_read_time = db.Column(db.DateTime, nullable=False, default=datetime.fromtimestamp(0).replace(tzinfo=None))
    
    __table_args__ = (
        db.UniqueConstraint('username', 'group_number', name='_user_group_uc'),
    )

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
    time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow) 

class Session(db.Model):
    __tablename__ = 'sessions'
    username = db.Column(db.String(50), primary_key=True, unique=True)
    token = db.Column(db.String(200), nullable=False)

# -------------------- INDEX CREATION (for performance) --------------------
index_ddl_msg = DDL('CREATE INDEX idx_messages_group_time ON messages (group_number, time)')
event.listen(Message.__table__, 'after_create', index_ddl_msg.execute_if(dialect='postgresql'))

index_ddl_status = DDL('CREATE INDEX idx_groupstatus_user_group ON group_status (username, group_number)')
event.listen(GroupStatus.__table__, 'after_create', index_ddl_status.execute_if(dialect='postgresql'))


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
    db.create_all() 

# -------------------- LOGIC HELPERS --------------------

def get_group_metadata(user, group_number):
    """Fetches group metadata including unread count and last message time."""
    grp = Group.query.get(group_number)
    if not grp:
        return None
        
    is_creator = grp.creator == user
    
    # 1. Get the user's last read time for this group
    status = GroupStatus.query.filter_by(username=user, group_number=group_number).first()
    # Default to the UNIX epoch if no status exists
    last_read_time = status.last_read_time if status else datetime.fromtimestamp(0).replace(tzinfo=None)

    # 2. Get the last message time
    last_message = Message.query.filter_by(group_number=group_number).order_by(Message.time.desc()).first()
    last_message_time = last_message.time if last_message else None

    # 3. Calculate unread count (messages WHERE time > last_read_time)
    if last_message_time and last_message_time > last_read_time:
        unread_count = Message.query.filter(
            Message.group_number == group_number,
            Message.time > last_read_time
        ).count()
    else:
        unread_count = 0

    return {
        "name": grp.name, 
        "number": group_number, 
        "is_creator": is_creator,
        "unread_count": unread_count,
        "last_message_time": last_message_time.isoformat() if last_message_time else None,
    }

# -------------------- ROOT/SIGNUP/LOGIN/LOGOUT (Unchanged) --------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "success": True,
        "message": "🚀 OneChat API is running! Database connection active."
    })

@app.route("/signup", methods=["POST"])
def signup():
    # ... (Signup logic from original) ...
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

@app.route("/login", methods=["POST"])
def login():
    # ... (Login logic from original) ...
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

@app.route("/logout", methods=["POST"])
def logout():
    # ... (Logout logic from original) ...
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
        
    # Initialize GroupStatus for the creator
    new_status = GroupStatus(username=user, group_number=group_number)
    db.session.add(new_status)

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

    # Initialize GroupStatus for the joining user
    new_status = GroupStatus(username=user, group_number=group_number)
    db.session.add(new_status)
        
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
        
    # 🌟 NEW: Delete GroupStatus for the user
    GroupStatus.query.filter_by(username=user, group_number=group_number).delete()

    # Check if the user was the creator and if the group is now empty
    if group.creator == user:
        if not group.members:
            # If creator leaves and no one is left, delete the group
            Message.query.filter_by(group_number=group_number).delete()
            GroupStatus.query.filter_by(group_number=group_number).delete() # Delete all statuses
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

    if group.creator != user:
        return jsonify({"success": False, "message": "Only the group admin can delete the group!"}), 403

    # Remove group from all members' group lists
    for member_username in (group.members or []):
        member = User.query.get(member_username)
        if member and group_number in (member.groups or []):
            member.groups.remove(group_number)

    # Delete all messages and statuses
    Message.query.filter_by(group_number=group_number).delete()
    GroupStatus.query.filter_by(group_number=group_number).delete()

    # Delete the group itself
    db.session.delete(group)
    db.session.commit()
    return jsonify({"success": True, "message": f"Group '{group.name}' and all messages deleted successfully!"})

# -------------------- GET PROFILE AND GROUPS (MODIFIED) --------------------
@app.route("/profile_and_groups", methods=["POST"])
def get_profile_and_groups():
    data = request.get_json() or {}
    token = data.get("token")

    user = authenticate(token)
    if not user:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401

    user_obj = User.query.get(user)
    if not user_obj:
        return jsonify({"success": False, "message": "User not found!"}), 404
        
    user_groups = []
    for gnum in (user_obj.groups or []):
        metadata = get_group_metadata(user, gnum)
        if metadata:
            user_groups.append(metadata)

    return jsonify({
        "success": True,
        "username": user,
        "name": user_obj.name,
        "groups": user_groups
    })

# -------------------- UPDATE PROFILE (Unchanged) --------------------
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

# -------------------- SEND MESSAGE (Unchanged) --------------------
@app.route("/send_message", methods=["POST"])
def send_message():
    data = request.get_json() or {}
    token = data.get("token")
    group_number = data.get("groupNumber")
    text = data.get("message")

    user = authenticate(token)
    if not user:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401

    group = Group.query.get(group_number)
    if not group or user not in (group.members or []):
        return jsonify({"success": False, "message": "Group not found or you are not a member!"}), 404
    
    if not text:
        return jsonify({"success": False, "message": "Message cannot be empty!"}), 400


    new_message = Message(
        sender=user,
        message=text,
        group_number=group_number,
        time=datetime.utcnow() 
    )
    db.session.add(new_message)
    db.session.commit()
    
    # 🌟 NEW: Mark group as read on successful send 
    status = GroupStatus.query.filter_by(username=user, group_number=group_number).first()
    if status:
        status.last_read_time = new_message.time
        db.session.commit()
        
    return jsonify({
        "success": True, 
        "message": "Message sent!",
        "time": new_message.time.isoformat()
    })

# -------------------- MARK READ (NEW ENDPOINT) --------------------
@app.route("/mark_read", methods=["POST"])
def mark_read():
    data = request.get_json() or {}
    token = data.get("token")
    group_number = data.get("groupNumber")

    user = authenticate(token)
    if not user:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401
    
    # Get the latest message time in the group
    latest_message = Message.query.filter_by(group_number=group_number).order_by(Message.time.desc()).first()
    
    if not latest_message:
        # If no messages exist, we mark as the earliest possible time
        read_time = datetime.fromtimestamp(0).replace(tzinfo=None)
    else:
        # Mark as read up to the time of the latest message
        read_time = latest_message.time

    # Update the GroupStatus entry
    status = GroupStatus.query.filter_by(username=user, group_number=group_number).first()
    
    if not status:
        # This shouldn't happen if user is a member, but handle it by creating a new status
        status = GroupStatus(username=user, group_number=group_number, last_read_time=read_time)
        db.session.add(status)
    else:
        status.last_read_time = read_time

    db.session.commit()
    return jsonify({"success": True, "message": "Group marked as read."})


# -------------------- GET MESSAGES (SYNC ENDPOINT - Unchanged logic) --------------------
@app.route("/get_messages/<group_number>", methods=["POST"])
def get_messages(group_number):
    data = request.get_json() or {}
    token = data.get("token")
    last_synced_time = data.get("last_synced_time") 

    user = authenticate(token)
    if not user:
        return jsonify({"success": False, "message": "Unauthorized!"}), 401
    
    # Check if the user is a member of the group
    group = Group.query.get(group_number)
    if not group or user not in (group.members or []):
        return jsonify({"success": False, "message": "Group not found or you are not a member!"}), 404
    
    # Base query: filter by group number
    query = Message.query.filter_by(group_number=group_number)
    
    # IMPLEMENT INCREMENTAL SYNC
    if last_synced_time:
        try:
            # Parse the ISO 8601 string received from the client
            last_time = datetime.fromisoformat(last_synced_time.replace('Z', '+00:00'))
            
            # Filter messages where the server time is strictly GREATER than the client's last time
            query = query.filter(Message.time > last_time)
            app.logger.info(f"Syncing group {group_number} for {user} since {last_synced_time}")
            
        except ValueError:
            # If the timestamp is invalid, log it and return *all* messages
            app.logger.warning(f"Invalid last_synced_time received: {last_synced_time}. Returning all messages.")
            

    # Apply ordering and execute
    group_messages = query.order_by(Message.time.asc()).all()

    return jsonify({
        "success": True,
        "messages": [
            {"sender": m.sender, "message": m.message, "time": m.time.isoformat()}
            for m in group_messages
        ]
    })

# -------------------- MESSAGE CLEANUP (Unchanged) --------------------
def cleanup_messages():
    with app.app_context():
        RETENTION_HOURS = 168 # 7 days
        
        while True:
            try:
                now = datetime.utcnow()
                cutoff_time = now - timedelta(hours=RETENTION_HOURS)
                
                # Delete messages older than the cutoff
                deleted_msg = Message.query.filter(Message.time < cutoff_time).delete(synchronize_session='fetch')
                # Also clean up GroupStatus entries for non-existent groups just in case
                active_group_numbers = [g.group_number for g in Group.query.with_entities(Group.group_number).all()]
                deleted_status = GroupStatus.query.filter(GroupStatus.group_number.notin_(active_group_numbers)).delete(synchronize_session='fetch')
                
                db.session.commit()
                app.logger.info(f"Cleanup thread: Deleted {deleted_msg} messages and {deleted_status} stale statuses.")
            except Exception as e:
                app.logger.exception("Cleanup thread error: %s", e)
                db.session.rollback()
            time.sleep(3600 * 6)  # Run cleanup every 6 hours

threading.Thread(target=cleanup_messages, daemon=True).start()

# -------------------- RUN SERVER --------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000)) 
    app.run(host="0.0.0.0", port=port, debug=True)
