# system_blog/forms.py

from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from models import User, Role
from flask_login import current_user

# Formulário de Registro de Usuário
class RegistrationForm(FlaskForm):
    username = StringField('Nome de Usuário',validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired(), Length(min=6, max=60)])
    confirm_password = PasswordField('Confirme a Senha',validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrar')

    # Validador personalizado para verificar se o nome de usuário já existe
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Esse nome de usuário já existe. Por favor, escolha outro.')

    # Validador personalizado para verificar se o e-mail já existe
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Esse e-mail já está em uso. Por favor, use outro.')


# Formulário de Login
class LoginForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired()])
    remember = BooleanField('Lembrar-me')
    submit = SubmitField('Login')


# Formulário de Atualização de Perfil
class UpdateAccountForm(FlaskForm):
    username = StringField('Nome de Usuário',validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',validators=[DataRequired(), Email()])
    submit = SubmitField('Atualizar')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Esse nome de usuário já existe. Por favor, escolha outro.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Esse e-mail já está em uso. Por favor, use outro.')

# Formulário para a criação e edição de posts
class PostForm(FlaskForm):
    title = StringField('Título', validators=[DataRequired()])
    content = TextAreaField('Conteúdo', validators=[DataRequired()])
    submit = SubmitField('Postar')

# Formulário para solicitar a redefinição de senha
class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Solicitar Redefinição de Senha')

    # Validador personalizado para verificar se o e-mail existe
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('Não há conta com esse e-mail. Você deve se registrar primeiro.')


# Formulário para redefinir a senha
class ResetPasswordForm(FlaskForm):
    password = PasswordField('Nova Senha', validators=[DataRequired(), Length(min=6, max=60)])
    confirm_password = PasswordField('Confirme a Nova Senha',validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Redefinir Senha')

# Formulário de Administração de Papéis 
class AdminUserRoleForm(FlaskForm):
    """Formulário para administradores mudarem o papel (Role) de outro usuário."""
    role_id = SelectField('Papel do Usuário', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Atualizar Papel')