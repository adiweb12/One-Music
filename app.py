import os
import jwt
import datetime
import json
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, join_room, leave_room, emit
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

# Load environment variables
load_dotenv()

# --- Flask App Initialization & Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

if app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgres://"):
    # SQLAlchemy requires postgresql://
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql://", 1)


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading') 

# --- Constants ---
TOKEN_EXPIRATION_DAYS = 7


# =========================================================
#                 DATABASE MODELS (SQLAlchemy)
# =========================================================

# User Model (Handles user registration and authentication)
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    # Stores a list of group numbers the user belongs to
    groups = db.Column(ARRAY(db.String), default=[]) 

# Group Model (Handles chat groups and message history)
class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    # Unique number/identifier for joining/messaging
    number = db.Column(db.String(80), unique=True, nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # Stores a list of user IDs (integers) who are members
    members = db.Column(ARRAY(db.Integer), default=[])
    # Stores message history as a JSON array of objects (using JSONB for efficiency)
    messages = db.Column(JSONB, default=[]) 

@app.before_first_request
def create_tables():
    """Create database tables if they don't exist."""
    db.create_all()


# =========================================================
#             AUTHENTICATION & HELPER FUNCTIONS
# =========================================================

def auth_required(f):
    """Decorator to authenticate requests based on JWT token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        data = request.get_json()
        token = data.get('token')
        
        if not token:
            return jsonify({"success": False, "message": "Token is missing!"}), 401

        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user_id = payload['user_id']
            
            user = User.query.get(user_id)
            if not user:
                 return jsonify({"success": False, "message": "User not found."}), 404
            
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "Token is expired."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "message": "Token is invalid."}), 401
        except Exception:
            return jsonify({"success": False, "message": "Authentication failed."}), 401
            
        return f(user_id, *args, **kwargs)
    return decorated

def get_user_details(user_id):
    """Retrieves username and name from user_id."""
    user = User.query.get(user_id)
    return user.username, user.name if user else (None, None)


# =========================================================
#                   HTTP ROUTES (API)
# =========================================================

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    name = data.get('name')

    if not all([username, password, name]):
        return jsonify({"success": False, "message": "Missing fields"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"success": False, "message": "Username already exists"}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    new_user = User(username=username, password=hashed_password, name=name)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"success": True, "message": "User created successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        token_payload = {
            'user_id': user.id, # Store SQL ID (integer)
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=TOKEN_EXPIRATION_DAYS),
            'iat': datetime.datetime.utcnow()
        }
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            "success": True, 
            "message": "Login successful", 
            "token": token
        }), 200
    else:
        return jsonify({"success": False, "message": "Invalid username or password"}), 401

@app.route('/logout', methods=['POST'])
@auth_required
def logout(user_id):
    return jsonify({"success": True, "message": "Logged out successfully"}), 200

@app.route('/profile', methods=['POST'])
@auth_required
def profile(user_id):
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    user_groups_data = []
    
    for group_number in user.groups:
        group = Group.query.filter_by(number=group_number).first()
        if group:
            is_creator = group.creator_id == user_id
            user_groups_data.append({
                "name": group.name,
                "number": group.number,
                "is_creator": is_creator
            })

    return jsonify({
        "success": True,
        "username": user.username,
        "name": user.name,
        "groups": user_groups_data
    }), 200

@app.route('/update_profile', methods=['POST'])
@auth_required
def update_profile(user_id):
    data = request.get_json()
    new_name = data.get('newName')
    
    if not new_name:
        return jsonify({"success": False, "message": "New name required"}), 400

    user = User.query.get(user_id)
    if user:
        user.name = new_name
        db.session.commit()
        return jsonify({"success": True, "message": "Name updated successfully"}), 200
    return jsonify({"success": False, "message": "User not found"}), 404


# Group Management

@app.route('/create_group', methods=['POST'])
@auth_required
def create_group(user_id):
    data = request.get_json()
    group_name = data.get('groupName')
    group_number = data.get('groupNumber')
    
    if not all([group_name, group_number]):
        return jsonify({"success": False, "message": "Group name and number required"}), 400

    if Group.query.filter_by(number=group_number).first():
        return jsonify({"success": False, "message": "Group number already in use"}), 409

    # Create Group
    new_group = Group(
        name=group_name,
        number=group_number,
        creator_id=user_id,
        members=[user_id],
        messages=[]
    )
    db.session.add(new_group)

    # Add group number to user's list
    user = User.query.get(user_id)
    if user:
        user.groups.append(group_number)
        db.session.commit()
        
    return jsonify({"success": True, "message": f"Group '{group_name}' created successfully"}), 201

@app.route('/join_group', methods=['POST'])
@auth_required
def join_group(user_id):
    data = request.get_json()
    group_number = data.get('groupNumber')
    
    if not group_number:
        return jsonify({"success": False, "message": "Group number required"}), 400

    group = Group.query.filter_by(number=group_number).first()
    if not group:
        return jsonify({"success": False, "message": "Group not found"}), 404

    if user_id in group.members:
        return jsonify({"success": False, "message": "Already a member of this group"}), 400

    # Add user to group's member list
    group.members.append(user_id)
    
    # Add group to user's groups list
    user = User.query.get(user_id)
    if user:
        user.groups.append(group_number)
        db.session.commit()

    return jsonify({"success": True, "message": f"Successfully joined group {group.name}"}), 200

@app.route('/get_messages/<string:group_number>', methods=['POST'])
@auth_required
def get_messages(user_id, group_number):
    group = Group.query.filter_by(number=group_number).first()
    if not group or user_id not in group.members:
        return jsonify({"success": False, "message": "Not authorized to view this chat"}), 403

    raw_messages = group.messages
    resolved_messages = []
    user_cache = {}

    for msg in raw_messages:
        sender_id = msg['sender_id']
        
        if sender_id not in user_cache:
            username, name = get_user_details(sender_id)
            user_cache[sender_id] = name if name else username
        
        sender_display = user_cache[sender_id]
        
        resolved_messages.append({
            "sender": sender_display,
            "message": msg['message'],
            "time": msg['timestamp'] 
        })

    return jsonify({"success": True, "messages": resolved_messages}), 200


# =========================================================
#                 SOCKETIO EVENTS (Real-Time)
# =========================================================

user_session = {} # Socket SID -> user data

# --- SOCKET AUTHENTICATION ---
@socketio.on('connect')
def handle_connect():
    token = request.headers.get('token')
    if not token:
        print("Socket connection rejected: No token")
        return False
        
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        user_id = payload['user_id']
        
        username, name = get_user_details(user_id)
        
        if not username:
             print(f"Socket connection rejected: User not found for ID {user_id}")
             return False

        user_session[request.sid] = {
            'user_id': user_id,
            'username': username,
            'name': name,
            'display_name': name if name else username
        }
        print(f"Client connected: {user_session[request.sid]['display_name']} (SID: {request.sid})")
        
    except Exception as e:
        print(f"Socket connection rejected: Authentication Error: {e}")
        return False

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in user_session:
        user_session.pop(request.sid)
    print(f"Client disconnected: (SID: {request.sid})")


@socketio.on('join_group')
def on_join(data):
    group_number = data.get('groupNumber')
    if not group_number:
        return
        
    session_data = user_session.get(request.sid)
    if not session_data:
        return
        
    user_id = session_data['user_id']
    group = Group.query.filter_by(number=group_number).first()
    
    if group and user_id in group.members:
        join_room(group_number)
        print(f"{session_data['display_name']} joined room: {group_number}")

@socketio.on('send_message')
def handle_message(data):
    group_number = data.get('groupNumber')
    message = data.get('message')
    
    if not all([group_number, message]):
        return

    session_data = user_session.get(request.sid)
    if not session_data:
        return

    user_id = session_data['user_id']
    display_name = session_data['display_name']
    
    group = Group.query.filter_by(number=group_number).first()
    
    if not group or user_id not in group.members:
        emit('error', {'message': 'You are no longer a member of this group.'})
        return
    
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 1. Prepare message object for DB storage
    db_message = {
        "sender_id": user_id,
        "message": message,
        "timestamp": timestamp
    }

    # 2. Save message to PostgreSQL group history (Append to JSONB array)
    
    # We load the existing messages, append the new one, and save the full array.
    # This is less performant than a native array append, but SQLAlchemy array field
    # handling requires this pattern or raw SQL which is more complex.
    updated_messages = group.messages
    updated_messages.append(db_message)
    group.messages = updated_messages
    db.session.commit()
    
    # 3. Prepare message object for real-time emission
    emit_message = {
        "sender": display_name,
        "message": message,
        "time": timestamp
    }

    # 4. Emit the message to all clients in the group room
    emit('receive_message', emit_message, room=group_number)
    print(f"Message in {group_number} from {display_name}: {message[:20]}...")

# =========================================================
#                        RUN SERVER
# =========================================================

if __name__ == '__main__':
    # When using SQLAlchemy, ensure to run within the Flask application context 
    # to avoid errors during table creation/DB access.
    with app.app_context():
        create_tables()
        socketio.run(app, debug=True, port=5000)
