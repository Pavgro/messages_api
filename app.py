from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
from werkzeug.security import generate_password_hash, check_password_hash


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


@app.route('/users<user_id>', methods=['GET'])
def get_user():
    return ''


@app.route('/users', methods=['POST'])
def register_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, id=data["id"])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'new user created'})


if __name__ == '__main__':
    app.run(debug=True)
