// -------------------- FLASK SERVER (app.py) --------------------
// This section assumes the code in untitled2.txt continued with the Python server logic.
// The provided code is a single file combining Dart and Python.

import os
import time
import threading
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt # PyJWT
import secrets # For generating tokens

app = Flask(__name__)

# --- CONFIGURATION ---
# Database URI for SQLAlchemy (e.g., PostgreSQL or SQLite for Render)
# Using os.environ.get is crucial for Render deployment
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://onechat_nhc9_user:JoXwS5h0cfjKLYVV0XMeaXsqhgWBKxjm@dpg-d3efbpggjchc738litc0-a/onechat_nhc9')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Secret key for JWT and session management
app.config['SECRET_KEY'] = 'a-super-secret-key-that-should-be-in-env-variables' # Use os.environ.get in production

db = SQLAlchemy(app)

# --- MODELS ---

# Association table for Group and User (Many-to-Many relationship)
group_members = db.Table('group_members',
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(100), nullable=True) # Display name
    token = db.Column(db.String(200), unique=True, nullable=True)
    token_expiry = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'username': self.username,
            'name': self.name or self.username,
        }

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    number = db.Column(db.String(50), unique=True, nullable=False) # The unique ID used by the client
    creator = db.Column(db.String(80), nullable=False) # Username of the creator
    
    members = db.relationship('User', secondary=group_members, lazy='subquery',
                              backref=db.backref('groups', lazy=True))

    def to_dict(self, current_user_username):
        return {
            'name': self.name,
            'number': self.number,
            'creator': self.creator,
            'is_creator': self.creator == current_user_username,
            'member_count': len(self.members)
        }

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_number = db.Column(db.String(50), db.ForeignKey('group.number'), nullable=False)
    sender = db.Column(db.String(80), db.ForeignKey('user.username'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    time = db.Column(db.DateTime, default=datetime.utcnow) # Server time stamp

    def to_dict(self):
        return {
            'sender': self.sender,
            'message': self.message,
            'time': self.time.isoformat() + 'Z' # UTC ISO format with Z
        }

# --- DECORATORS ---

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        data = request.get_json()
        if data and 'token' in data:
            token = data['token']

        if not token:
            return jsonify({'success': False, 'message': 'Token is missing!'}), 401

        try:
            # Check if token is in the database and not expired
            current_user = User.query.filter_by(token=token).first()
            if not current_user or current_user.token_expiry < datetime.utcnow():
                 return jsonify({'success': False, 'message': 'Token is invalid or expired!'}), 401
        except:
            return jsonify({'success': False, 'message': 'Token is invalid or expired!'}), 401
        
        return f(current_user, *args, **kwargs)

    return decorated

# --- SETUP ROUTE (Run once to create DB tables) ---
@app.before_first_request
def create_tables():
    db.create_all()

# --- AUTH ROUTES ---

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    name = data.get('name')

    if not username or not password or not name:
        return jsonify({'success': False, 'message': 'Missing fields!'}), 400

    if len(password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters.'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': 'Username already exists.'}), 409

    new_user = User(username=username, name=name)
    new_user.set_password(password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'success': True, 'message': 'User created successfully!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        # Generate a new secure token (e.g., a long random string)
        token = secrets.token_urlsafe(32)
        expiry = datetime.utcnow() + timedelta(hours=24) # Token expires in 24 hours

        user.token = token
        user.token_expiry = expiry
        db.session.commit()

        return jsonify({'success': True, 'message': 'Login successful!', 'token': token})
    
    return jsonify({'success': False, 'message': 'Invalid username or password!'}), 401

@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    # Invalidate the token
    current_user.token = None
    current_user.token_expiry = None
    db.session.commit()
    return jsonify({'success': True, 'message': 'Logged out successfully!'})

# --- PROFILE ROUTES ---

@app.route('/profile', methods=['POST'])
@token_required
def get_profile(current_user):
    # Fetch all groups the user is a member of
    user_groups = current_user.groups
    
    groups_data = [group.to_dict(current_user.username) for group in user_groups]
    
    return jsonify({
        'success': True,
        'username': current_user.username,
        'name': current_user.name or current_user.username,
        'groups': groups_data
    })

@app.route('/update_profile', methods=['POST'])
@token_required
def update_profile(current_user):
    data = request.get_json()
    new_name = data.get('newName')
    
    if not new_name:
        return jsonify({'success': False, 'message': 'Display name cannot be empty.'}), 400

    try:
        current_user.name = new_name
        db.session.commit()
        return jsonify({'success': True, 'message': 'Profile updated successfully!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500


# --- GROUP MANAGEMENT ROUTES ---

@app.route('/create_group', methods=['POST'])
@token_required
def create_group(current_user):
    data = request.get_json()
    group_name = data.get('groupName')
    group_number = data.get('groupNumber')
    
    if not group_name or not group_number:
        return jsonify({'success': False, 'message': 'Missing group name or ID.'}), 400

    if Group.query.filter_by(number=group_number).first():
        return jsonify({'success': False, 'message': f'Group ID "{group_number}" already taken.'}), 409
    
    new_group = Group(name=group_name, number=group_number, creator=current_user.username)
    new_group.members.append(current_user)

    try:
        db.session.add(new_group)
        db.session.commit()
        return jsonify({'success': True, 'message': f'Group "{group_name}" created successfully!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500

@app.route('/join_group', methods=['POST'])
@token_required
def join_group(current_user):
    data = request.get_json()
    group_number = data.get('groupNumber')
    
    group = Group.query.filter_by(number=group_number).first()
    if not group:
        return jsonify({'success': False, 'message': 'Group not found.'}), 404
        
    if current_user in group.members:
        return jsonify({'success': False, 'message': 'You are already a member of this group.'}), 400

    try:
        group.members.append(current_user)
        db.session.commit()
        return jsonify({'success': True, 'message': f'Successfully joined group {group.name}.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500

@app.route('/leave_group', methods=['POST'])
@token_required
def leave_group(current_user):
    data = request.get_json()
    group_number = data.get('groupNumber')
    
    group = Group.query.filter_by(number=group_number).first()
    if not group:
        return jsonify({'success': False, 'message': 'Group not found.'}), 404

    # 🌟 FIX (2/2): Prevent the creator from leaving; they must delete the group
    if group.creator == current_user.username:
        return jsonify({'success': False, 'message': 'As the group creator, you must delete the group instead of leaving it.'}), 403
        
    # Remove the user from the group's members list
    if current_user in group.members:
        try:
            group.members.remove(current_user)
            db.session.commit()
            return jsonify({'success': True, 'message': f'Successfully left group {group.name}.'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500
    else:
        return jsonify({'success': False, 'message': 'You are not a member of this group.'}), 400

@app.route('/delete_group', methods=['POST'])
@token_required
def delete_group(current_user):
    data = request.get_json()
    group_number = data.get('groupNumber')
    
    group = Group.query.filter_by(number=group_number).first()
    if not group:
        return jsonify({'success': False, 'message': 'Group not found.'}), 404
        
    if group.creator != current_user.username:
        return jsonify({'success': False, 'message': 'Only the group creator can delete the group.'}), 403

    try:
        # Delete all messages associated with the group
        Message.query.filter_by(group_number=group_number).delete(synchronize_session='fetch')
        # Delete the group itself (group_members association table handles cascade implicitly)
        db.session.delete(group)
        db.session.commit()
        return jsonify({'success': True, 'message': f'Group "{group.name}" successfully deleted.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500


# --- MESSAGE ROUTES ---

@app.route('/send_message', methods=['POST'])
@token_required
def send_message(current_user):
    data = request.get_json()
    group_number = data.get('groupNumber')
    message_content = data.get('message')

    group = Group.query.filter_by(number=group_number).first()
    if not group or current_user not in group.members:
        return jsonify({'success': False, 'message': 'Group not found or you are not a member.'}), 404

    new_message = Message(
        group_number=group_number,
        sender=current_user.username,
        message=message_content,
        time=datetime.utcnow() # Use the server's UTC time
    )
    
    try:
        db.session.add(new_message)
        db.session.commit()
        # Return the definitive server time for the client to update its local copy
        return jsonify({'success': True, 'message': 'Message sent.', 'time': new_message.time.isoformat() + 'Z'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500


@app.route('/get_messages/<group_number>', methods=['POST'])
@token_required
def get_messages(current_user, group_number):
    data = request.get_json()
    last_synced_time_str = data.get('last_synced_time')

    group = Group.query.filter_by(number=group_number).first()
    if not group or current_user not in group.members:
        return jsonify({'success': False, 'message': 'Group not found or you are not a member.'}), 404

    # Base query: get all messages for this group
    query = Message.query.filter_by(group_number=group_number)
    
    # Filter by time if the client provides a last synced time
    if last_synced_time_str:
        try:
            # Parse the client's last synced time (it should be ISO format UTC)
            last_synced_time = datetime.fromisoformat(last_synced_time_str.replace('Z', '+00:00'))
            
            # Filter for messages *strictly newer* than the last synced time
            query = query.filter(Message.time > last_synced_time)
        except ValueError:
            # If time string is invalid, ignore the filter and send all available messages
            pass 

    # Order by time and fetch
    messages = query.order_by(Message.time.asc()).limit(100).all() # Limit for performance
    
    return jsonify({
        'success': True,
        'messages': [message.to_dict() for message in messages]
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

