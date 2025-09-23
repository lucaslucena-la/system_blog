from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_bcrypt import Bcrypt   
import os

app = Flask(__name__)

# === Config ===
# Use uma SECRET_KEY fixa (ideal via variável de ambiente)
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

login_manager.login_view = 'login'

import views
#print("ROTAS CARREGADAS:", app.url_map)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # Evita rodar a thread de citação 2x no reloader do Flask
    app.run(debug=True, use_reloader=False)
