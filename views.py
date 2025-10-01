
import os
import requests
import json
from threading import Thread
from functools import wraps
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from flask import render_template, url_for, flash, redirect, request, abort, jsonify
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
from app import app, db, bcrypt, mail
from models import User, Post, Role, is_moderator, is_admin
from forms import (RegistrationForm, LoginForm, UpdateAccountForm, PostForm,ResetPasswordRequestForm, ResetPasswordForm, AdminUserRoleForm)
from werkzeug.utils import secure_filename
import secrets


# --- CITAÇÃO (estado global simples) ---
quote_of_the_day = {
    'content': 'Carregando citação...',
    'content_en': 'Loading quote...',
    'author': 'Sistema',
    'thread': None
}

# --- DECORADORES DE PERMISSÃO ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not is_admin(current_user):
            flash('Acesso negado. Você não tem permissão de Administrador.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def moderator_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not is_moderator(current_user):
            flash('Acesso negado. Você não tem permissão de Moderação.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# --- THREAD: BUSCA & TRADUÇÃO DA CITAÇÃO ---

def get_and_translate_quote():
    global quote_of_the_day
    headers = {'User-Agent': 'SystemBlog-Flask-App/1.0'}

    try:
        r = requests.get('https://api.quotable.io/random', timeout=5, headers=headers, verify=False)
        r.raise_for_status()
        q = r.json()
        content_en = q.get('content', 'Could not fetch content.')
        author = q.get('author', 'Unknown')

        t = requests.get(
            f'https://api.mymemory.translated.net/get?q={content_en}&langpair=en|pt',
            timeout=5, headers=headers, verify=False
        )
        t.raise_for_status()
        td = t.json()
        translated = td.get('responseData', {}).get('translatedText', content_en) or content_en

        quote_of_the_day['content'] = translated
        quote_of_the_day['content_en'] = content_en
        quote_of_the_day['author'] = author

    except requests.exceptions.SSLError as e:
        app.logger.error(f"ERRO SSL: {e}")
        quote_of_the_day.update({'content': "Erro SSL...", 'content_en': "SSL Error.", 'author': "Erro SSL"})
    except requests.RequestException as e:
        app.logger.error(f"Erro API Citação/Tradução: {e}")
        quote_of_the_day.update({'content': "Erro de conexão.", 'content_en': "Connection error.", 'author': "Erro de Conexão"})
    except (json.JSONDecodeError, KeyError) as e:
        app.logger.error(f"Erro ao processar dados da API: {e}")
        quote_of_the_day.update({'content': "Erro ao processar resposta.", 'content_en': "Parsing error.", 'author': "Erro de Dados"})
    finally:
        quote_of_the_day['thread'] = None


@app.before_request
def start_quote_thread():
    global quote_of_the_day
    if quote_of_the_day.get('thread') is None or not quote_of_the_day['thread'].is_alive():
        th = Thread(target=get_and_translate_quote, daemon=True)
        th.start()
        quote_of_the_day['thread'] = th
        app.logger.info("Thread de citação assíncrona iniciada.")


# --- API da citação (usada no front via fetch) ---

@app.route("/get_quote")
def get_quote():
    pt = quote_of_the_day.get('content', 'Indisponível')
    en = quote_of_the_day.get('content_en', pt)
    author = quote_of_the_day.get('author', 'Desconhecido')
    return jsonify({"ok": True, "quote_en": en, "quote_pt": pt, "author": author})


# --- E-MAILS ---

def send_confirmation_email(user):
    """
    Envia e-mail de confirmação de conta.
    Usa MAIL_DEFAULT_SENDER (ou MAIL_USERNAME) configurado no app.py.
    """
    token = user.get_confirmation_token()
    msg = Message(
        subject='Confirmação de Conta',
        recipients=[user.email]  # não definir 'sender' aqui -> usa o default do app
    )
    msg.body = f"""Para confirmar sua conta, clique no link:
    {url_for('confirm_account', token=token, _external=True)}

    Se você não se registrou em nosso blog, ignore este e-mail.
    """
    try:
        # Log defensivo para ajudar a depurar caso falhe
        if not (app.config.get('MAIL_DEFAULT_SENDER') or app.config.get('MAIL_USERNAME')):
            app.logger.error("Nenhum remetente configurado (MAIL_DEFAULT_SENDER/MAIL_USERNAME).")
        mail.send(msg)
    except Exception as e:
        app.logger.error(f"Falha ao enviar e-mail de confirmação: {e}")


def send_reset_email(user):
    """
    Envia e-mail de redefinição de senha (token expira em 10 min).
    Usa MAIL_DEFAULT_SENDER (ou MAIL_USERNAME) configurado no app.py.
    """
    token = user.get_confirmation_token(expires_sec=600)
    msg = Message(
        subject='Redefinição de Senha',
        recipients=[user.email]  # não definir 'sender' aqui -> usa o default do app
    )
    msg.body = f"""Para redefinir sua senha, visite:
    {url_for('reset_token', token=token, _external=True)}

    Se você não solicitou, ignore este e-mail.
    """
    try:
        if not (app.config.get('MAIL_DEFAULT_SENDER') or app.config.get('MAIL_USERNAME')):
            app.logger.error("Nenhum remetente configurado (MAIL_DEFAULT_SENDER/MAIL_USERNAME).")
        mail.send(msg)
    except Exception as e:
        app.logger.error(f"Falha ao enviar e-mail de reset: {e}")


# --- HELPER: redirecionar por papel após login ---

def redirect_by_role(user):
    if is_admin(user):
        return url_for('admin_users')
    elif is_moderator(user):
        return url_for('moderator_dashboard')
    else:
        return url_for('user_dashboard')


# --- HOME ---

@app.route("/")
@app.route("/home")
def home():
    quote = quote_of_the_day['content']
    author = quote_of_the_day['author']
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    return render_template('home.html', title='Início', posts=posts, quote=quote, author=author,is_moderator=is_moderator, is_admin=is_admin)


# --- AUTENTICAÇÃO ---

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(redirect_by_role(current_user))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        
        default_role = Role.query.filter_by(name="Padrão").first()
        user = User(
        username=form.username.data,
        email=form.email.data,
        password=hashed_password,
        role=default_role  # ← atribui papel padrão
    )

        db.session.add(user)
        db.session.commit()
        
        send_confirmation_email(user)


        flash(f'Conta criada! Enviamos um e-mail para {user.email}.', 'info')
        return redirect(url_for('login'))
    return render_template('register.html', title='Registro', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(redirect_by_role(current_user))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if user.is_active:
                login_user(user, remember=form.remember.data)
                flash('Login bem-sucedido!', 'success')

                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(redirect_by_role(user))
            else:
                flash('Sua conta ainda não foi ativada. Verifique seu e-mail.', 'warning')
        else:
            flash('Login sem sucesso. Email ou senha incorretos.', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('Você fez logout com sucesso.', 'success')
    return redirect(url_for('home'))


@app.route("/confirm/<token>")
def confirm_account(token):
    if current_user.is_authenticated:
        return redirect(redirect_by_role(current_user))

    user = User.verify_confirmation_token(token)
    if user is None:
        flash('Token inválido ou expirado.', 'danger')
        return redirect(url_for('register'))

    if user.is_active:
        flash('Essa conta já estava ativa. Faça login.', 'info')
        return redirect(url_for('login'))

    user.is_active = True
    db.session.commit()
    flash('Conta ativada! Agora você pode fazer login.', 'success')
    return redirect(url_for('login'))


# --- RESET DE SENHA ---

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(redirect_by_role(current_user))

    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
        flash('Se esse e-mail existir, enviamos as instruções.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Resetar Senha', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(redirect_by_role(current_user))

    user = User.verify_confirmation_token(token, max_age=600)
    if user is None:
        flash('Token inválido ou expirado.', 'danger')
        return redirect(url_for('reset_request'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed
        db.session.commit()
        flash('Senha resetada! Faça login.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Redefinir Senha', form=form)


# --- CONTA & PERFIL ---

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)
    form_picture.save(picture_path)
    return picture_fn


@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if getattr(form, 'picture', None) and form.picture.data:
            profile_dir = os.path.join(app.root_path, 'static', 'profile_pics')
            os.makedirs(profile_dir, exist_ok=True)
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file

        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Sua conta foi atualizada com sucesso!', 'success')
        return redirect(url_for('account'))

    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email

    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Perfil', image_file=image_file, form=form)


@app.route("/user/<string:username>")
def user_posts(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(author=user).order_by(Post.date_posted.desc()).all()
    quote = quote_of_the_day['content']
    author = quote_of_the_day['author']
    return render_template('user_posts.html', title=f'Posts de {user.username}', posts=posts,user=user, quote=quote, author=author)


# --- DASHBOARDS ---

@app.route("/dashboard")    
@login_required
def user_dashboard():
    posts = Post.query.filter_by(author=current_user).order_by(Post.date_posted.desc()).all()
    return render_template('user_dashboard.html', title='Meu Painel', posts=posts)

@app.route("/moderator")
@login_required
@moderator_required
def moderator_dashboard():
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    return render_template('moderator_dashboard.html', title='Moderação', posts=posts)


# --- POSTS ---

@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Seu post foi criado!', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title='Novo Post', form=form, legend='Criar Novo Post')

@app.route("/post/<int:post_id>")
def post(post_id):
    post = db.session.get(Post, post_id)
    if post is None:
        abort(404)
    return render_template('post.html', title=post.title, post=post,is_moderator=is_moderator, is_admin=is_admin)

@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = db.session.get(Post, post_id)
    if post is None:
        abort(404)
    if post.author != current_user:
        flash('Você não tem permissão para editar este post.', 'danger')
        return redirect(url_for('post', post_id=post.id))

    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Seu post foi atualizado!', 'success')
        return redirect(url_for('post', post_id=post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
    return render_template('create_post.html', title='Editar Post', form=form, legend='Editar Post')

@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = db.session.get(Post, post_id)
    if post is None:
        abort(404)

    # Autor OU moderador OU admin podem excluir
    # Moderador pode excluir QUALQUER post, EXCETO se o autor for admin.
    is_authorized = (post.author == current_user) or is_admin(current_user) or (is_moderator(current_user) and not is_admin(post.author))
    if not is_authorized:
        flash('Você não tem permissão para excluir este post.', 'danger')
        return redirect(url_for('post', post_id=post.id))

    db.session.delete(post)
    db.session.commit()
    flash('O post foi excluído!', 'success')
    return redirect(url_for('home'))


# --- ADMIN ---

@app.route("/admin/users")
@admin_required
def admin_users():
    users = User.query.all()
    roles = Role.query.order_by(Role.id).all()
    role_choices = [(r.id, r.name) for r in roles]
    return render_template('admin_users.html', title='Administração de Usuários',users=users, AdminUserRoleForm=AdminUserRoleForm, role_choices=role_choices)

@app.route("/admin/user/<int:user_id>/role", methods=['POST'])
@admin_required
def admin_user_role_update(user_id):
    target_user = db.session.get(User, user_id)
    if target_user is None:
        abort(404)

    if target_user.id == current_user.id:
        flash('Você não pode mudar seu próprio papel de administrador.', 'warning')
        return redirect(url_for('admin_users'))

    form = AdminUserRoleForm()
    form.role_id.choices = [(r.id, r.name) for r in Role.query.order_by(Role.id).all()]

    if form.validate_on_submit():
        new_role = db.session.get(Role, form.role_id.data)
        if new_role:
            target_user.role_id = new_role.id
            db.session.commit()
            flash(f'O papel de "{target_user.username}" foi alterado para "{new_role.name}".', 'success')
        else:
            flash('Papel selecionado inválido.', 'danger')
    else:
        app.logger.error(f"Erro de validação ao tentar atualizar o papel: {form.errors}")
        flash('Erro de validação ao tentar atualizar o papel.', 'danger')

    return redirect(url_for('admin_users'))
