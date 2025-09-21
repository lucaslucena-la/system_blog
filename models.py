
from app import db, login_manager
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app
from flask_login import UserMixin
from datetime import datetime


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)
    is_active = db.Column(db.Boolean, default=False)

    # Método para gerar um token de confirmação para a ativação da conta
    def get_confirmation_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    # Método estático para verificar um token de confirmação
    @staticmethod
    def verify_confirmation_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            # Tenta desserializar o token para obter o ID do usuário
            user_id = s.loads(token)['user_id']
        except:
            # Retorna None se o token for inválido ou expirar
            return None
        # Retorna o objeto User com base no ID
        return User.query.get(user_id)

    # Método para uma representação amigável do objeto
    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.role}')"

# Definição da classe Post, que representa a tabela de posts do blog
class Post(db.Model):
    # Define as colunas da tabela Post
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # Chave estrangeira que conecta um post a um usuário
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Método para uma representação amigável do objeto
    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"
