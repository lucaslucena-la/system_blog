from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_bcrypt import Bcrypt   
import os
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'      # 'smtp.googlemail.com' também funciona
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
mail = Mail(app)
bcrypt = Bcrypt(app) 
s = URLSafeTimedSerializer(app.config['SECRET_KEY']) 

login_manager.login_view = 'login'
login_manager.login_message_category = 'info' 
login_manager.login_view = 'login'


from models import User
def load_user(user_id):
    """Carrega um objeto User do DB a partir do user_id armazenado na sessão."""
    # Usa db.session.get para busca direta por chave primária
    try:
        return db.session.get(User, int(user_id))
    except ValueError:
        return None

#print("ROTAS CARREGADAS:", app.url_map)
import views


if __name__ == '__main__':
    with app.app_context():
        from models import Role
        db.create_all()

        if Role.query.count() == 0:
            print ("Inicializando Ppéis de Uduário")
            default_role = Role(id=1, name='Padrão', can_moderate=False, can_admin=False)
            moderador_role = Role(id=2, name='Moderador', can_moderate=False, can_admin=False)
            adm_role = Role(id=3, name='Moderador', can_moderate=False, can_admin=True)
            db.session.add_all([default_role, moderador_role, adm_role])
            db.session.commit()
            print("Papéis de usuário (Padrão, Moderador, Administrador) criados no DB.")

    app.run(debug=True, use_reloader=False)
