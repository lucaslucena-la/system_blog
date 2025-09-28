from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer
import os
from dotenv import load_dotenv  

# Carrega variáveis do .env 
load_dotenv()

app = Flask(__name__)

# Configurações 
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# E-mail (lido do .env)
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'no-reply@local.test')

# --- Inicialização das Extensões ---
db = SQLAlchemy(app)
login_manager = LoginManager(app)
mail = Mail(app)
bcrypt = Bcrypt(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- Carregador de Usuário ---
from models import User

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except ValueError:
        return None

# Importa views depois das extensões
import views


from models import is_admin, is_moderator
app.jinja_env.globals.update(is_admin=is_admin, is_moderator=is_moderator)


if __name__ == '__main__':
    with app.app_context():
        from models import Role
        db.create_all()

        if Role.query.count() == 0:
            print("Inicializando papéis de usuário...")
            default_role = Role(id=1, name='Padrão', can_moderate=False, can_admin=False)
            moderator_role = Role(id=2, name='Moderador', can_moderate=True, can_admin=False)
            admin_role = Role(id=3, name='Administrador', can_moderate=True, can_admin=True)
            db.session.add_all([default_role, moderator_role, admin_role])
            db.session.commit()
            print("Papéis criados com sucesso.")

    app.run(debug=True)
