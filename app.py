import os
import jwt
import datetime
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, join_room, emit
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

# Load environment variables from .env file
load_dotenv()

# --- Flask App Initialization & Configuration ---
app = Flask(__name__)

# ⚠️ VALIDATION FIX for TypeError: Expected a string value (SECRET_KEY missing)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY']:
    # Fail immediately if the secret key is not configured
    raise ValueError("SECRET_KEY environment variable is not set. Please check your .env or Render configuration.")
# -----------------------------------------------

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Adjust URI for SQLAlchemy compatibility
if app.config['SQLALCHEMY_DATABASE_URI'] and app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql://", 1)


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
# Use 'threading' as a safe async mode for Gunicorn/Render deployments
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading') 

# --- Constants ---
TOKEN_EXPIRATION_DAYS = 7


# =========================================================
#                 DATABASE MODELS (SQLAlchemy)
# =========================================================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True) 
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    groups = db.Column(ARRAY(db.String), default=[]) 

class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    number = db.Column(db.String(80), unique=True, nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False) 
    members = db.Column(ARRAY(db.Integer), default=[])
    messages = db.Column(JSONB, default=[]) 

# --- Database Initialization Function ---
def create_tables():
    """Create database tables if they don't exist."""
    with app.app_context():
        # NOTE: If you need to fix the 'users.id does not exist' error,
        # temporarily change db.create_all() to:
        # db.drop_all()
        # db.create_all()
        # and then revert it after one successful deployment.
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
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=TOKEN_EXPIRATION_DAYS),
            'iat': datetime.datetime.utcnow()
        }
        # This line now safely uses a guaranteed string SECRET_KEY
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

    new_group = Group(
        name=group_name,
        number=group_number,
        creator_id=user_id,
        members=[user_id],
        messages=[]
    )
    db.session.add(new_group)

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

    group.members.append(user_id)
    
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

user_session = {} # Maps Socket SID to user data

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
             return False

        user_session[request.sid] = {
            'user_id': user_id,
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

    # 2. Save message to PostgreSQL group history (Appending to JSONB)
    updated_messages = list(group.messages)
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
#                        STARTUP
# =========================================================

# ⚠️ FIX for 'before_first_request' error on Render/Gunicorn: 
# Call the table creation function in the global scope (within app context)
with app.app_context():
    create_tables()

if __name__ == '__main__':
    # For local testing
    socketio.run(app, debug=True, port=5000)
