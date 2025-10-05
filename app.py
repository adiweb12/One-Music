from flask import Flask, request
from flask_socketio import SocketIO, emit, join_room
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os

# --- Configuration ---
app = Flask(__name__)

# Render provides the database URL via the DATABASE_URL environment variable
# Use a fallback for local testing
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://user:password@localhost:5432/chatdb')
if DATABASE_URL.startswith("postgres://"):
    # SQLAlchemy sometimes requires postgresql:// for compatibility
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_render_secret_key_here')

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ----------------------------------------------------------------------
# 1. Database Models
# ----------------------------------------------------------------------

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
            'isMe': False, # When loaded from DB, it's not the local sender
            'timestamp': self.timestamp.strftime("%H:%M")
        }

# ----------------------------------------------------------------------
# 2. Socket Handlers
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
        
        # Load and send previous messages from the database
        messages = Message.query.filter_by(room_id=room_id).order_by(Message.timestamp.asc()).limit(50).all()
        
        # Send a history event to the joining client only
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
# 3. Setup and Run
# ----------------------------------------------------------------------

if __name__ == '__main__':
    # Create tables if they don't exist
    with app.app_context():
        db.create_all()
        print("Database tables ensured.")
        
    print("Starting Flask-SocketIO Server...")
    # Render requires binding to 0.0.0.0 and uses the PORT environment variable
    port = int(os.environ.get('PORT', 5000)) 
    socketio.run(app, host='0.0.0.0', port=port)
