from app import db, login_manager
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import current_app
from flask_login import UserMixin
from datetime import datetime

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def _ts():
    # helper para ter um serializer consistente
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

class Role(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(20), unique= True, nullable = False )

    can_moderate = db.Column(db.Boolean, default = False)
    can_admin = db.Column(db.Boolean, default = False)

    users = db.relationship('User', backref='role', lazy=True)

    def __repr__(self):
        return f"Role('{self.name}', Mod:{self.can_moderate}, Admin:{self.can_admin})"


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)
    is_active = db.Column(db.Boolean, default=False)

    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False, default=1) 
    
    posts = db.relationship('Post', backref='author', lazy=True)


    def get_confirmation_token(self, expires_sec=1800):
        return _ts().dumps({'user_id': self.id}, salt='confirm-salt')

    @staticmethod
    def verify_confirmation_token(token, max_age=1800):
        try:
            data = _ts().loads(token, salt='confirm-salt', max_age=max_age)
        except (BadSignature, SignatureExpired):
            return None
        return User.query.get(data['user_id'])

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.role}')"

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"


#Funções auxiliares para Permissão

def is_moderator(user):
    return user.is_authenticated and user.role.can_moderate if hasattr(user, 'role') else False

def is_admin(user):
    return user.is_authenticated and user.role.can_admin if hasattr(user, 'role') else False
