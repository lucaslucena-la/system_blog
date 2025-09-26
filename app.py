from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_bcrypt import Bcrypt   
import os
from itsdangerous import URLSafeTimedSerializer # Necessário para o Serializer

app = Flask(__name__)

# === Configurações (Ajuste suas variáveis de ambiente aqui) ===
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
# Lembre-se de definir as variáveis de ambiente EMAIL_USER e EMAIL_PASS no seu terminal!
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

# --- Carregador de Usuário para Flask-Login ---
# Importa o modelo User AQUI para que load_user possa ser definido
from models import User 

@login_manager.user_loader
def load_user(user_id):
    """Carrega um objeto User do DB a partir do user_id armazenado na sessão."""
    try:
        # Usa db.session.get() (melhor prática no Flask-SQLAlchemy 3.x)
        return db.session.get(User, int(user_id))
    except ValueError:
        return None

# Importa as views DEPOIS de inicializar app, db, etc.
import views 


if __name__ == '__main__':
    with app.app_context():
        from models import Role # Importa Role para inicialização
        db.create_all()
        
        # Lógica de inicialização de Papéis (CRÍTICO para Permissão)
        if Role.query.count() == 0:
            print("Inicializando Papéis de Usuário...")
            # Definimos os IDs explicitamente para garantir que 'Padrão' seja ID=1, 
            # conforme o default em models.py
            default_role = Role(id=1, name='Padrão', can_moderate=False, can_admin=False)
            moderator_role = Role(id=2, name='Moderador', can_moderate=True, can_admin=False)
            admin_role = Role(id=3, name='Administrador', can_moderate=True, can_admin=True)
            db.session.add_all([default_role, moderator_role, admin_role])
            db.session.commit()
            print("Papéis de usuário (Padrão, Moderador, Administrador) criados no DB.")
            
    # Rodar o Flask
    app.run(debug=True)
