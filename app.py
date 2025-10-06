# app.py
# Production-ready Flask + SQLAlchemy + Flask-SocketIO backend

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_socketio import SocketIO, emit, join_room, leave_room, close_room
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import logging

# ---------- Configuration ----------
app = Flask(__name__)
CORS(app)

# DATABASE
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Fallback to SQLite for dev
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL or "sqlite:///chat.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change_me')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------- Models ----------
group_members = db.Table(
    'group_members',
    db.Column('group_id', db.Integer, db.ForeignKey('groups.id', ondelete='CASCADE'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False, default='User')

    def to_dict(self):
        return {'id': self.id, 'phone': self.phone, 'username': self.username}

class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    room_id = db.Column(db.String(80), unique=True, nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    members = db.relationship('User', secondary=group_members, backref=db.backref('groups', lazy='dynamic'))

    def to_dict(self):
        return {'id': self.id, 'name': self.name, 'room_id': self.room_id, 'creator_id': self.creator_id}

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.String(80), nullable=False, index=True)
    sender = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self, current_user=None):
        return {
            'id': self.id,
            'room_id': self.room_id,
            'sender': self.sender,
            'message': self.message,
            'timestamp': self.timestamp.strftime("%H:%M"),
            'isMe': (current_user is not None and self.sender == current_user)
        }

# ---------- Helpers ----------
def make_room_id(name):
    return f"group_{name.strip().lower().replace(' ', '_')}"

# ---------- Ensure tables exist ----------
with app.app_context():
    db.create_all()
    logger.info("Database tables created/ensured.")

# ---------- Routes ----------
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json() or {}
    phone = data.get('phone')
    password = data.get('password')
    username = data.get('username') or (f'User_{phone[-4:]}' if phone else None)

    if not phone or not password or not username:
        return jsonify({'message': 'Missing phone, username or password'}), 400

    if User.query.filter((User.phone == phone) | (User.username == username)).first():
        return jsonify({'message': 'User or phone already exists'}), 409

    try:
        hashed = generate_password_hash(password)
        user = User(phone=phone, password_hash=hashed, username=username)
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'User created', 'username': user.username, 'id': user.id}), 201
    except Exception as e:
        db.session.rollback()
        logger.exception("Signup DB error")
        return jsonify({'message': f'Database error: {str(e)}'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    phone = data.get('phone')
    password = data.get('password')
    if not phone or not password:
        return jsonify({'message': 'Missing phone or password'}), 400

    user = User.query.filter_by(phone=phone).first()
    if user and check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Login successful', 'username': user.username, 'id': user.id}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/create_group', methods=['POST'])
def create_group():
    data = request.get_json() or {}
    group_name = data.get('name')
    creator_username = data.get('creator')
    if not group_name or not creator_username:
        return jsonify({'message': 'Missing name or creator'}), 400

    creator = User.query.filter_by(username=creator_username).first()
    if not creator:
        return jsonify({'message': 'Creator not found'}), 404

    room_id = make_room_id(group_name)
    if Group.query.filter_by(room_id=room_id).first():
        return jsonify({'message': 'Group name already taken'}), 409

    try:
        g = Group(name=group_name, room_id=room_id, creator_id=creator.id)
        g.members.append(creator)
        db.session.add(g)
        db.session.commit()
        return jsonify({'message': 'Group created', 'room_id': room_id, 'name': group_name}), 201
    except Exception as e:
        db.session.rollback()
        logger.exception("Create group DB error")
        return jsonify({'message': f'Database error: {str(e)}'}), 500

@app.route('/user_groups/<string:username>', methods=['GET'])
def user_groups(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404
    groups = [g.to_dict() for g in user.groups]
    return jsonify({'groups': groups}), 200

@app.route('/delete_group', methods=['POST'])
def delete_group():
    data = request.get_json() or {}
    room_id = data.get('room_id')
    username = data.get('username')
    if not room_id or not username:
        return jsonify({'message': 'Missing room_id or username'}), 400

    g = Group.query.filter_by(room_id=room_id).first()
    user = User.query.filter_by(username=username).first()
    if not g or not user:
        return jsonify({'message': 'Group or User not found'}), 404
    if g.creator_id != user.id:
        return jsonify({'message': 'Only the creator can delete the group'}), 403

    try:
        Message.query.filter_by(room_id=room_id).delete(synchronize_session='fetch')
        db.session.delete(g)
        db.session.commit()
        socketio.emit('group_deleted', {'room_id': room_id}, room=room_id)
        close_room(room_id)
        return jsonify({'message': f'Group {room_id} deleted'}), 200
    except Exception as e:
        db.session.rollback()
        logger.exception("Delete group DB error")
        return jsonify({'message': f'Database error: {str(e)}'}), 500

@app.route('/leave_group', methods=['POST'])
def leave_group():
    data = request.get_json() or {}
    room_id = data.get('room_id')
    username = data.get('username')
    if not room_id or not username:
        return jsonify({'message': 'Missing room_id or username'}), 400

    g = Group.query.filter_by(room_id=room_id).first()
    user = User.query.filter_by(username=username).first()
    if not g or not user:
        return jsonify({'message': 'Group or User not found'}), 404
    if g.creator_id == user.id:
        return jsonify({'message': 'Creator must delete the group, not leave it'}), 403

    try:
        if user in g.members:
            g.members.remove(user)
            db.session.commit()
            socketio.emit('receive_message', {
                'sender': 'SYSTEM',
                'message': f'{username} has left the group.',
                'room_id': room_id,
                'isMe': False,
                'timestamp': datetime.utcnow().strftime("%H:%M")
            }, room=room_id)
            return jsonify({'message': f'{username} left group {room_id}'}), 200
        else:
            return jsonify({'message': 'User not a group member'}), 400
    except Exception as e:
        db.session.rollback()
        logger.exception("Leave group DB error")
        return jsonify({'message': f'Database error: {str(e)}'}), 500

@app.route('/')
def index():
    return jsonify({'status': 'ok', 'time': datetime.utcnow().isoformat()}), 200

# ---------- Socket Handlers ----------
@socketio.on('connect')
def on_connect():
    logger.info(f"Client connected: {request.sid}")
    emit('status', {'msg': 'Connected to Chat Server!'})

@socketio.on('join_chat')
def on_join(data):
    room_id = data.get('room_id')
    username = data.get('username', 'A User')
    if not room_id:
        emit('error', {'message': 'Missing room_id'})
        return
    join_room(room_id)
    logger.info(f"{username} joined room {room_id}")
    messages = Message.query.filter_by(room_id=room_id).order_by(Message.timestamp.asc()).limit(50).all()
    emit('message_history', {'messages': [m.to_dict(current_user=username) for m in messages], 'room_id': room_id}, room=request.sid)
    emit('receive_message', {'sender': 'SYSTEM', 'message': f'{username} joined the room.', 'room_id': room_id, 'isMe': False, 'timestamp': datetime.utcnow().strftime("%H:%M")}, room=room_id)

@socketio.on('typing')
def on_typing(data):
    room_id = data.get('room_id')
    username = data.get('username', 'Someone')
    is_typing = data.get('typing', True)
    if room_id:
        emit('typing', {'room_id': room_id, 'username': username, 'typing': is_typing}, room=room_id, include_self=False)

@socketio.on('send_message')
def on_send_message(data):
    room_id = data.get('room_id')
    sender = data.get('sender', 'Unknown')
    message_text = data.get('message', '')
    if not room_id or not message_text:
        emit('error', {'message': 'Missing room_id or message'})
        return

    try:
        msg = Message(room_id=room_id, sender=sender, message=message_text, timestamp=datetime.utcnow())
        db.session.add(msg)
        db.session.commit()

        payload = {'sender': sender, 'message': message_text, 'room_id': room_id, 'isMe': False, 'timestamp': msg.timestamp.strftime("%H:%M")}
        emit('receive_message', payload, room=room_id)
        logger.info(f"Saved message in {room_id} by {sender}")
    except Exception as e:
        db.session.rollback()
        logger.exception("Send message DB error")
        emit('error', {'message': 'Database error when saving message'})

@socketio.on('disconnect')
def on_disconnect():
    logger.info(f"Client disconnected: {request.sid}")

# ---------- Run ----------
port = int(os.environ.get('PORT', 5000))
logger.info(f"Starting server on port {port}")
socketio.run(app, host='0.0.0.0', port=port)
