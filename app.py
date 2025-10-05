from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room, close_room
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from werkzeug.security import generate_password_hash, check_password_hash

# --- Configuration ---
app = Flask(__name__)

# Render provides the database URL via the DATABASE_URL environment variable
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://user:password@localhost:5432/chatdb')
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_render_secret_key_here')

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ----------------------------------------------------------------------
# 1. Database Models
# ----------------------------------------------------------------------

# User model for storing credentials
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False, default='User')

# Group model for managing groups
class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    room_id = db.Column(db.String(50), unique=True, nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Define relationship to members
    members = db.relationship('User', secondary='group_members', backref=db.backref('groups', lazy='dynamic'))

# Many-to-Many relationship for Group Members
group_members = db.Table('group_members',
    db.Column('group_id', db.Integer, db.ForeignKey('group.id', ondelete='CASCADE'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True)
)

# Message model for chat history
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.String(50), nullable=False)
    sender = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'room_id': self.room_id,
            'sender': self.sender,
            'message': self.message,
            'isMe': False,
            'timestamp': self.timestamp.strftime("%H:%M")
        }

# ----------------------------------------------------------------------
# 2. Flask HTTP Routes (Authentication & Group Management)
# ----------------------------------------------------------------------

# --- USER AUTHENTICATION ---

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    phone = data.get('phone')
    password = data.get('password')
    username = data.get('username') or f'User_{phone[-4:]}'

    if not phone or not password:
        return jsonify({'message': 'Missing phone or password'}), 400

    if User.query.filter_by(phone=phone).first() or User.query.filter_by(username=username).first():
        return jsonify({'message': 'User or phone already exists'}), 409

    hashed_password = generate_password_hash(password)
    
    new_user = User(phone=phone, password_hash=hashed_password, username=username)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User created successfully', 'username': new_user.username, 'id': new_user.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Database error: {str(e)}'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    phone = data.get('phone')
    password = data.get('password')

    user = User.query.filter_by(phone=phone).first()

    if user and check_password_hash(user.password_hash, password):
        return jsonify({
            'message': 'Login successful', 
            'username': user.username, 
            'id': user.id
        }), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

# --- GROUP MANAGEMENT ---

@app.route('/create_group', methods=['POST'])
def create_group():
    data = request.get_json()
    group_name = data.get('name')
    creator_username = data.get('creator')

    user = User.query.filter_by(username=creator_username).first()
    if not user:
        return jsonify({'message': 'Creator not found'}), 404
    
    room_id = f"group_{group_name.lower().replace(' ', '_')}"

    if Group.query.filter_by(room_id=room_id).first():
        return jsonify({'message': 'Group name already taken'}), 409

    new_group = Group(name=group_name, room_id=room_id, creator_id=user.id)
    
    try:
        new_group.members.append(user)
        db.session.add(new_group)
        db.session.commit()
        return jsonify({'message': 'Group created', 'room_id': room_id, 'name': group_name}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Database error: {str(e)}'}), 500

@app.route('/user_groups/<string:username>', methods=['GET'])
def get_user_groups(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Fetch groups the user is a member of
    group_list = [{'name': g.name, 'room_id': g.room_id} for g in user.groups.all()]
    
    return jsonify({'groups': group_list}), 200

@app.route('/delete_group', methods=['POST'])
def delete_group():
    data = request.get_json()
    room_id = data.get('room_id')
    username = data.get('username')

    group = Group.query.filter_by(room_id=room_id).first()
    user = User.query.filter_by(username=username).first()

    if not group or not user:
        return jsonify({'message': 'Group or User not found'}), 404

    if group.creator_id != user.id:
        return jsonify({'message': 'Only the creator can delete the group'}), 403

    try:
        # Delete the group which will cascade delete members and messages (if configured correctly)
        # We manually delete Messages to ensure clean-up if cascade is tricky
        Message.query.filter_by(room_id=room_id).delete(synchronize_session='fetch')
        db.session.delete(group)
        db.session.commit()
        
        socketio.emit('group_deleted', {'room_id': room_id}, room=room_id)
        close_room(room_id) 
        
        return jsonify({'message': f'Group {room_id} deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Database error: {str(e)}'}), 500

@app.route('/leave_group', methods=['POST'])
def leave_group():
    data = request.get_json()
    room_id = data.get('room_id')
    username = data.get('username')

    group = Group.query.filter_by(room_id=room_id).first()
    user = User.query.filter_by(username=username).first()

    if not group or not user:
        return jsonify({'message': 'Group or User not found'}), 404

    try:
        # Check if the user is the creator and block leaving (must delete instead)
        if group.creator_id == user.id:
            return jsonify({'message': 'Creator must delete the group, not leave it'}), 403
            
        # Remove the user from the group's members list
        group.members.remove(user)
        db.session.commit()

        # Notify the room
        socketio.emit('receive_message', {
            'sender': 'SYSTEM', 
            'message': f'{username} has left the group.', 
            'room_id': room_id, 
            'isMe': False,
            'timestamp': datetime.utcnow().strftime("%H:%M")
        }, room=room_id)
        
        return jsonify({'message': f'{username} left group {room_id}'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Database error: {str(e)}'}), 500

# ----------------------------------------------------------------------
# 3. Socket Handlers (Real-time Chat)
# ----------------------------------------------------------------------

@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')
    emit('status', {'msg': 'Connected to Render Chat Server!'})

@socketio.on('join_chat')
def on_join(data):
    room_id = data.get('room_id')
    username = data.get('username', 'A User')
    
    if room_id:
        join_room(room_id)
        print(f'{username} joined room: {room_id}')
        
        messages = Message.query.filter_by(room_id=room_id).order_by(Message.timestamp.asc()).limit(50).all()
        
        emit('message_history', 
             {'messages': [m.to_dict() for m in messages], 'room_id': room_id}, 
             room=request.sid)

@socketio.on('send_message')
def handle_message(data):
    room_id = data.get('room_id')
    sender = data.get('sender', 'Unknown')
    message_text = data.get('message', 'No content')
    
    # 1. Save to Database
    new_message = Message(room_id=room_id, sender=sender, message=message_text)
    db.session.add(new_message)
    db.session.commit()
    
    # 2. Prepare response for real-time broadcast
    response_data = {
        'sender': sender,
        'message': message_text,
        'room_id': room_id,
        'isMe': False, 
        'timestamp': datetime.utcnow().strftime("%H:%M")
    }
    
    print(f'DB Saved and Broadcast to room {room_id} from {sender}: {message_text}')
    
    # 3. Broadcast to all clients in the room
    emit('receive_message', response_data, room=room_id)

# ----------------------------------------------------------------------
# 4. Setup and Run
# ----------------------------------------------------------------------

if __name__ == '__main__':
    with app.app_context():
        # Ensure all models (User, Group, Message, and the association table) are created
        db.create_all()
        print("Database tables ensured.")
        
    print("Starting Flask-SocketIO Server...")
    port = int(os.environ.get('PORT', 5000)) 
    socketio.run(app, host='0.0.0.0', port=port)
