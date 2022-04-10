from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messages.db'

db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))


class Messages(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_name = db.Column(db.String(50))
    sender_id = db.Column(db.Integer)
    receiver_name = db.Column(db.String(50))
    receiver_id = db.Column(db.Integer)
    message = db.Column(db.Text)
    subject = db.Column(db.String(100))
    creation_date = db.Column(db.DateTime, default=datetime.utcnow())
    read = db.Column(db.Boolean)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], options={"verify_signature": False})
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated


@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):

    users = User.query.all()

    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['id'] = user.id
        output.append(user_data)
    return jsonify({'users': output})


@app.route('/users', methods=['POST'])
def register_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, id=data["id"])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'new user created'})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', '401',  {'WWW-Authenticate': 'Basic realm = "Login required'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', '401',  {'WWW-Authenticate': 'Basic realm = "Login required'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.utcnow() + timedelta(minutes=30)},
                           app.config['SECRET_KEY'])
        return jsonify({'token': token})

    return make_response('Could not verify', '401', {'WWW-Authenticate': 'Basic realm = "Login required'})


@app.route('/messages', methods=['POST'])
@token_required
def write(current_user):
    data = request.get_json()
    new_message = Messages(subject=data['subject'], message=data['message'], sender_name=current_user.name,
                           sender_id=current_user.id, receiver_name=data['receiver_name'],
                           receiver_id=data['receiver_id'], read=False)
    db.session.add(new_message)
    db.session.commit()
    return jsonify({'message': "message sent"})


@app.route('/messages', methods=['GET'])
@token_required
def get_all_messages(current_user):
    messages = Messages.query.filter_by(receiver_id=current_user.id).all()
    output = []
    for message in messages:
        data = {}
        data['receiver_name'] = message.receiver_name
        data['receiver_id'] = message.receiver_id
        data['sender_name'] = message.sender_name
        data['sender_id'] = message.sender_id
        data['subject'] = message.subject
        data['text'] = message.message
        data['creation_date'] = message.creation_date
        data['id'] = message.id
        data['read'] = message.read
        output.append(data)
    return jsonify({f'{current_user.name} messages': output})


@app.route('/unread', methods=['GET'])
@token_required
def get_unread(current_user):
    messages = Messages.query.filter_by(receiver_id=current_user.id, read=False).all()
    if not messages:
        return jsonify({'message': 'No unread messages'})
    output = []
    for message in messages:
        data = {}
        data['receiver_name'] = message.receiver_name
        data['receiver_id'] = message.receiver_id
        data['subject'] = message.subject
        data['text'] = message.message
        data['creation_date'] = message.creation_date
        data['id'] = message.id
        data['read'] = message.read
        output.append(data)
    return jsonify({f'{current_user.name} unread messages': output})


@app.route('/messages/<message_id>', methods=['GET'])
@token_required
def read_message(current_user, message_id):
    message = Messages.query.filter_by(receiver_id=current_user.id, id=message_id).first()
    if not message:
        return jsonify({'message': 'message not found'})
    data = {}
    data['sender_id'] = message.sender_id
    data['sender_name'] = message.sender_name
    data['subject'] = message.subject
    data['text'] = message.message
    data['creation_date'] = message.creation_date
    data['id'] = message.id
    message.read = True
    db.session.commit()
    return jsonify(data)


@app.route('/messages/<message_id>', methods=['DELETE'])
@token_required
def delete_message(current_user, message_id):
    message = Messages.query.filter_by(receiver_id=current_user.id, id=message_id).first()
    if not message:
        return jsonify({'message': 'Message not found!'})

    db.session.delete(message)
    db.session.commit()

    return jsonify({'message': 'message deleted successfully'})


if __name__ == '__main__':
    app.run(debug=True)
