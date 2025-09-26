
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


quote_of_the_day = {
    'content': 'Carregando citação...',
    'content_en': 'Loading quote...',
    'author': 'Sistema',
    'thread': None
}

# --- DECORADORES PERSONALIZADOS PARA PERMISSÕES ---

def admin_required(f):
    """Restringe o acesso à rota apenas a usuários Administradores."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not is_admin(current_user):
            flash('Acesso negado. Você não tem permissão de Administrador.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def moderator_required(f):
    """Restringe o acesso à rota a Moderadores e Administradores."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not is_moderator(current_user):
            flash('Acesso negado. Você não tem permissão de Moderação.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function


# --- LÓGICA DE API ASSÍNCRONA E TRADUÇÃO (Em Thread) ---

def get_and_translate_quote():
    """Busca citação em thread e a traduz para o português."""
    global quote_of_the_day

    # Cabeçalho simples para evitar bloqueios de API
    headers = {'User-Agent': 'SystemBlog-Flask-App/1.0'}

    try:
        # 1) Buscar Citação (EN)
        # DEV: verify=False + aviso silenciado acima.
        quote_response = requests.get(
            'https://api.quotable.io/random',
            timeout=5,
            headers=headers,
            verify=False
        )
        quote_response.raise_for_status()
        quote_data = quote_response.json()
        content_en = quote_data.get('content', 'Could not fetch content.')
        author = quote_data.get('author', 'Unknown')

        # 2) Traduzir Conteúdo (EN -> PT)
        translation_url = 'https://api.mymemory.translated.net/get?q={}&langpair=en|pt'.format(content_en)
        translation_response = requests.get(
            translation_url,
            timeout=5,
            headers=headers,
            verify=False
        )
        translation_response.raise_for_status()
        translation_data = translation_response.json()

        translated_content = translation_data.get('responseData', {}).get('translatedText', content_en)
        if not translated_content:
            translated_content = content_en

        # 3) Armazenar globalmente (PT + EN + autor)
        quote_of_the_day['content'] = translated_content
        quote_of_the_day['content_en'] = content_en
        quote_of_the_day['author'] = author

    except requests.exceptions.SSLError as e:
        app.logger.error(f"ERRO SSL (Certificado): {e}. Tente instalar os certificados Python.")
        quote_of_the_day['content'] = "Erro SSL. Não foi possível conectar. Tente instalar os certificados Python."
        quote_of_the_day['content_en'] = "SSL Error."
        quote_of_the_day['author'] = "Erro SSL"
    except requests.RequestException as e:
        app.logger.error(f"Erro na requisição da API de Citação/Tradução: {e}")
        quote_of_the_day['content'] = "Não foi possível carregar ou traduzir a citação do dia. Erro de conexão."
        quote_of_the_day['content_en'] = "Connection error."
        quote_of_the_day['author'] = "Erro de Conexão"
    except (json.JSONDecodeError, KeyError) as e:
        app.logger.error(f"Erro ao processar dados da API: {e}")
        quote_of_the_day['content'] = "Erro ao processar a resposta da API de tradução."
        quote_of_the_day['content_en'] = "Parsing error."
        quote_of_the_day['author'] = "Erro de Dados"
    finally:
        # Garante que a thread seja re-inicializada se falhar (ou após um longo tempo)
        quote_of_the_day['thread'] = None


# Inicia a thread de busca da citação na primeira requisição para evitar bloqueio
@app.before_request
def start_quote_thread():
    """Verifica se a thread da citação está rodando e a inicia se necessário."""
    global quote_of_the_day
    if quote_of_the_day.get('thread') is None or not quote_of_the_day['thread'].is_alive():
        thread = Thread(target=get_and_translate_quote)
        thread.daemon = True
        thread.start()
        quote_of_the_day['thread'] = thread
        app.logger.info("Thread de citação assíncrona iniciada.")


# --- ROTA ASSÍNCRONA PARA ATUALIZAR A CITAÇÃO NO FRONT-END (usada via JS) ---

@app.route("/get_quote")
def get_quote():
    """
    Retorna a citação atual como JSON para ser buscada pelo front-end via JavaScript.
    Alinhado ao que o home.html espera: ok, quote_en, quote_pt, author.
    """
    pt = quote_of_the_day.get('content', 'Indisponível')
    en = quote_of_the_day.get('content_en', pt)
    author = quote_of_the_day.get('author', 'Desconhecido')

    return jsonify({
        "ok": True,
        "quote_en": en,
        "quote_pt": pt,
        "author": author
    })


# --- FUNÇÕES AUXILIARES DE E-MAIL ---

def send_confirmation_email(user):
    """Envia o e-mail de confirmação de conta."""
    from app import mail, app  # Importação local para evitar import circular
    from flask_mail import Message
    token = user.get_confirmation_token()

    # Prod: usa MAIL_USERNAME; Dev: cai no MAIL_DEFAULT_SENDER
    sender = app.config.get('MAIL_USERNAME') or app.config.get('MAIL_DEFAULT_SENDER')

    msg = Message(
        'Confirmação de Conta',
        sender=sender,
        recipients=[user.email]
    )
    msg.body = f"""Para confirmar sua conta, clique no seguinte link:
{url_for('confirm_account', token=token, _external=True)}

Se você não se registrou em nosso blog, por favor, ignore este e-mail.
"""
    try:
        mail.send(msg)
    except Exception as e:
        app.logger.error(f"Falha ao enviar e-mail de confirmação: {e}")


def send_reset_email(user):
    """Envia o e-mail de redefinição de senha."""
    from app import mail, app
    from flask_mail import Message
    token = user.get_confirmation_token(expires_sec=600)

    # Prod: usa MAIL_USERNAME; Dev: cai no MAIL_DEFAULT_SENDER
    sender = app.config.get('MAIL_USERNAME') or app.config.get('MAIL_DEFAULT_SENDER')

    msg = Message(
        'Redefinição de Senha',
        sender=sender,
        recipients=[user.email]
    )
    msg.body = f"""Para redefinir sua senha, visite o seguinte link:
{url_for('reset_token', token=token, _external=True)}

Se você não solicitou a redefinição de senha, por favor, ignore este e-mail.
"""
    try:
        mail.send(msg)
    except Exception as e:
        app.logger.error(f"Falha ao enviar e-mail de reset: {e}")


# --- ROTAS PRINCIPAIS ---

@app.route("/")
@app.route("/home")
def home():
    """Rota principal. Lista posts e exibe a citação do dia."""
    quote_data = quote_of_the_day
    quote = quote_data['content']
    author = quote_data['author']

    # Sem paginação por enquanto
    posts = Post.query.order_by(Post.date_posted.desc()).all()

    return render_template(
        'home.html',
        title='Início',
        posts=posts,
        quote=quote,
        author=author,
        is_moderator=is_moderator,
        is_admin=is_admin
    )


# --- AUTENTICAÇÃO ---

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegistrationForm()
    if form.validate_on_submit():
        from app import db  # Importação local
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        send_confirmation_email(user)

        flash(f'Conta criada! Um e-mail de confirmação foi enviado para {user.email}. Por favor, ative sua conta.', 'info')
        return redirect(url_for('login'))

    return render_template('register.html', title='Registro', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if user.is_active:
                login_user(user, remember=form.remember.data)
                next_page = request.args.get('next')
                flash('Login bem-sucedido!', 'success')
                return redirect(next_page) if next_page else redirect(url_for('home'))
            else:
                flash('Sua conta ainda não foi ativada. Por favor, verifique seu e-mail.', 'warning')
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
        return redirect(url_for('home'))

    user = User.verify_confirmation_token(token)

    if user is None:
        flash('Esse token de confirmação é inválido ou expirou.', 'danger')
        return redirect(url_for('register'))

    if user.is_active:
        flash('Essa conta já estava ativa. Por favor, faça login.', 'info')
        return redirect(url_for('login'))

    from app import db  # Importação local
    user.is_active = True
    db.session.commit()

    flash('Sua conta foi ativada! Agora você pode fazer login.', 'success')
    return redirect(url_for('login'))


# --- RESET DE SENHA ---

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
        flash('Se uma conta com esse e-mail existir, um e-mail foi enviado com instruções.', 'info')
        return redirect(url_for('login'))

    return render_template('reset_request.html', title='Resetar Senha', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    user = User.verify_confirmation_token(token, max_age=600)

    if user is None:
        flash('Esse token é inválido ou expirou. Por favor, solicite um novo.', 'danger')
        return redirect(url_for('reset_request'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        from app import db, bcrypt  # Importação local
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Sua senha foi resetada! Você pode fazer login agora.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_token.html', title='Redefinir Senha', form=form)


# --- GESTÃO DE CONTA E PERFIL ---

def save_picture(form_picture):
    """Salva a nova imagem de perfil no sistema de arquivos e retorna o nome do arquivo."""
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
        # Upload de imagem de perfil (se houver)
        if getattr(form, 'picture', None) and form.picture.data:
            profile_dir = os.path.join(app.root_path, 'static', 'profile_pics')
            if not os.path.exists(profile_dir):
                os.makedirs(profile_dir)

            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file

        from app import db  # Importação local
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

    return render_template(
        'user_posts.html',
        title=f'Posts de {user.username}',
        posts=posts,
        user=user,
        quote=quote,
        author=author
    )


# --- CRUD DE POSTS ---

@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        from app import db  # Importação local
        post = Post(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Seu post foi criado!', 'success')
        return redirect(url_for('home'))

    return render_template('create_post.html', title='Novo Post', form=form, legend='Criar Novo Post')


@app.route("/post/<int:post_id>")
def post(post_id):
    from app import db  # Importação local
    post = db.session.get(Post, post_id)
    if post is None:
        abort(404)
    return render_template('post.html', title=post.title, post=post, is_moderator=is_moderator, is_admin=is_admin)


@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    from app import db  # Importação local
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
    from app import db  # Importação local
    post = db.session.get(Post, post_id)
    if post is None:
        abort(404)

    is_authorized = (post.author == current_user) or is_moderator(current_user)

    if not is_authorized:
        flash('Você não tem permissão para excluir este post.', 'danger')
        return redirect(url_for('post', post_id=post.id))

    db.session.delete(post)
    db.session.commit()
    flash('O post foi excluído!', 'success')
    return redirect(url_for('home'))


# --- ADMINISTRAÇÃO DE PERMISSÕES ---

@app.route("/admin/users")
@admin_required
def admin_users():
    users = User.query.all()
    roles = Role.query.order_by(Role.id).all()
    role_choices = [(r.id, r.name) for r in roles]

    return render_template(
        'admin_users.html',
        title='Administração de Usuários',
        users=users,
        AdminUserRoleForm=AdminUserRoleForm,
        role_choices=role_choices
    )


@app.route("/admin/user/<int:user_id>/role", methods=['POST'])
@admin_required
def admin_user_role_update(user_id):
    from app import db  # Importação local
    target_user = db.session.get(User, user_id)
    if target_user is None:
        abort(404)

    if target_user.id == current_user.id:
        flash('Você não pode mudar seu próprio papel de administrador.', 'warning')
        return redirect(url_for('admin_users'))

    form = AdminUserRoleForm()
    # Carrega as opções de papel dinamicamente
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
