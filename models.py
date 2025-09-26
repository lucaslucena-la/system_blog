from app import db, login_manager
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import current_app
from flask_login import UserMixin
from datetime import datetime

# --- Configuração do Serializador ---
def _ts():
    """Gera uma instância do URLSafeTimedSerializer (itsdangerous)."""
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

# --- Definição de Papéis de Usuário (Permissões) ---
class Role(db.Model):
    """Modelo para definir os diferentes papéis de usuário (Padrão, Moderador, Admin)."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    can_moderate = db.Column(db.Boolean, default=False)  # Pode apagar posts de outros
    can_admin = db.Column(db.Boolean, default=False)     # Pode gerenciar usuários/papéis

    # O backref='role' CRIA a propriedade 'user.role' no modelo User.
    users = db.relationship('User', backref='role', lazy=True) 

    def __repr__(self):
        return f"Role('{self.name}', Mod:{self.can_moderate}, Admin:{self.can_admin})"

# --- Modelo de Usuário ---
class User(db.Model, UserMixin):
    """Modelo para a tabela de usuários com relação de Papel."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False) 
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg') 
    is_active = db.Column(db.Boolean, default=False) 

    # Coluna que armazena o ID do papel (Chave Estrangeira)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False, default=1) 
    
    # Relacionamento: Um usuário pode ter muitos posts
    posts = db.relationship('Post', backref='author', lazy=True)

    def get_confirmation_token(self, expires_sec=1800):
        """Gera um token seguro e com tempo de expiração para confirmação/reset."""
        return _ts().dumps({'user_id': self.id}, salt='confirm-salt')

    @staticmethod
    def verify_confirmation_token(token, max_age=1800):
        """Verifica se o token é válido e retorna o usuário."""
        try:
            data = _ts().loads(token, salt='confirm-salt', max_age=max_age)
        except (BadSignature, SignatureExpired):
            return None
        return db.session.get(User, data['user_id']) 

    def __repr__(self):
        # Acessa o nome do papel via 'self.role.name' (propriedade criada pelo backref)
        role_name = self.role.name if self.role else 'Desconhecido' 
        return f"User('{self.username}', '{self.email}', 'Role: {role_name}')"

# --- Modelo de Postagem (Post) ---
class Post(db.Model):
    """Modelo para a tabela de posts do blog."""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    
    # Chave estrangeira: Um post pertence a um usuário
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"

# --- Funções Auxiliares de Permissão ---
# Acessam o objeto Role criado pelo backref
def is_moderator(user):
    """Verifica se o usuário tem permissão de moderação (inclui admins)."""
    return user.is_authenticated and user.role.can_moderate if hasattr(user, 'role') else False

def is_admin(user):
    """Verifica se o usuário tem permissão de administração."""
    return user.is_authenticated and user.role.can_admin if hasattr(user, 'role') else False
