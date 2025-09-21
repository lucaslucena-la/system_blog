# system_blog/routes.py

# Importa as classes e funções necessárias do Flask e outras bibliotecas
import os
import requests
from threading import Thread
from flask import render_template, url_for, flash, redirect, request, jsonify, abort
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
from app import app, db, bcrypt, mail
from models import User, Post
from forms import (RegistrationForm, LoginForm, UpdateAccountForm, PostForm,
                   ResetPasswordRequestForm, ResetPasswordForm)

# Variável global para armazenar a citação do dia
quote_of_the_day = {}

# Função para buscar e traduzir a citação
def get_and_translate_quote():
    global quote_of_the_day
    try:
        # Busca uma citação aleatória da API Quotable
        quote_response = requests.get('https://api.quotable.io/random')
        quote_data = quote_response.json()
        content = quote_data.get('content')
        author = quote_data.get('author')

        if content and author:
            # Traduz o conteúdo da citação para o português
            # Usando uma API de tradução de exemplo. Você pode precisar
            # de uma chave de API para uma versão de produção.
            translation_url = 'https://api.mymemory.translated.net/get?q={}&langpair=en|pt'.format(content)
            translation_response = requests.get(translation_url)
            translation_data = translation_response.json()
            translated_content = translation_data['responseData']['translatedText']

            # Armazena a citação e a tradução
            quote_of_the_day = {
                'content': content,
                'author': author,
                'translated_content': translated_content
            }
        else:
            # Caso a API Quotable não retorne uma citação válida
            quote_of_the_day = {'translated_content': 'Não foi possível carregar a citação do dia.'}

    except Exception as e:
        # Em caso de erro na requisição ou tradução
        print(f"Erro ao buscar/traduzir a citação: {e}")
        quote_of_the_day = {'translated_content': 'Não foi possível carregar a citação do dia.'}

# Inicia a thread para buscar a citação assim que a aplicação for iniciada
thread = Thread(target=get_and_translate_quote)
thread.daemon = True # Garante que a thread será encerrada com a aplicação
thread.start()

# Rota da página inicial
@app.route("/")
@app.route("/home")
def home():
    # Obtém a página atual da URL (default é 1)
    page = request.args.get('page', 1, type=int)
    # Busca todos os posts, paginando 5 por página, ordenados por data
    posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template('home.html', posts=posts, quote=quote_of_the_day)

# Rota para o registro de usuário
@app.route("/register", methods=['GET', 'POST'])
def register():
    # Redireciona o usuário para a página inicial se ele já estiver logado
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    # Verifica se o formulário foi submetido e é válido
    if form.validate_on_submit():
        # Faz o hash da senha para armazená-la de forma segura
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        # Cria um novo usuário com os dados do formulário e a senha com hash
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        # Adiciona o usuário ao banco de dados e salva
        db.session.add(user)
        db.session.commit()
        # Envia o e-mail de confirmação
        send_confirmation_email(user)
        flash('Sua conta foi criada! Um e-mail de confirmação foi enviado.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Registrar', form=form)

# Função para enviar o e-mail de confirmação
def send_confirmation_email(user):
    token = user.get_confirmation_token()
    msg = Message('Confirmação de Conta',
                  sender=os.environ.get('EMAIL_USER'),
                  recipients=[user.email])
    # Cria o corpo do e-mail com o link de confirmação
    msg.body = f'''Para confirmar sua conta, visite o seguinte link:
{url_for('confirm_account', token=token, _external=True)}

Se você não solicitou este registro, por favor, ignore este e-mail.
'''
    mail.send(msg)

# Rota para confirmar a conta via e-mail
@app.route("/confirm_account/<token>")
def confirm_account(token):
    # Redireciona se o usuário já estiver logado
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    # Verifica o token
    user = User.verify_confirmation_token(token)
    if user is None:
        flash('O link de confirmação é inválido ou expirou.', 'danger')
        return redirect(url_for('register'))
    # Ativa a conta do usuário
    user.is_active = True
    db.session.commit()
    flash('Sua conta foi ativada! Você pode fazer login agora.', 'success')
    return redirect(url_for('login'))

# Rota para o login
@app.route("/login", methods=['GET', 'POST'])
def login():
    # Redireciona o usuário para a página inicial se ele já estiver logado
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    # Verifica se o formulário foi submetido e é válido
    if form.validate_on_submit():
        # Busca o usuário pelo e-mail
        user = User.query.filter_by(email=form.email.data).first()
        # Verifica se o usuário existe e se a senha está correta
        if user and user.is_active and bcrypt.check_password_hash(user.password, form.password.data):
            # Faz o login do usuário
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash(f'Bem-vindo, {user.username}!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        elif user and not user.is_active:
            flash('Sua conta não está ativa. Por favor, confirme seu e-mail.', 'warning')
        else:
            flash('Login sem sucesso. Por favor, verifique o e-mail e a senha.', 'danger')
    return render_template('login.html', title='Login', form=form)

# Rota para o logout
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

# Rota para o perfil do usuário
@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    form = UpdateAccountForm()
    # Preenche o formulário com os dados atuais do usuário
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Sua conta foi atualizada com sucesso!', 'success')
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('profile.html', title='Perfil', form=form)

# Rota para a página de criação de posts
@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        # Cria um novo post com os dados do formulário e o autor atual
        post = Post(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Seu post foi criado com sucesso!', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title='Novo Post', form=form, legend='Novo Post')

# Rota para a página de um post individual
@app.route("/post/<int:post_id>")
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', title=post.title, post=post)

# Rota para a página de edição de post
@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    # Verifica se o usuário atual é o autor do post
    if post.author != current_user:
        # Se não for, impede a edição
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Seu post foi atualizado com sucesso!', 'success')
        return redirect(url_for('post', post_id=post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
    return render_template('create_post.html', title='Atualizar Post',
                           form=form, legend='Atualizar Post')

# Rota para a exclusão de post
@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    # Verifica se o usuário atual é o autor, moderador ou administrador
    if post.author != current_user and current_user.role not in ['moderator', 'admin']:
        # Se não for, impede a exclusão
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Seu post foi excluído com sucesso!', 'success')
    return redirect(url_for('home'))

# Rota para a página de administração de usuários (apenas para administradores)
@app.route("/admin/users", methods=['GET', 'POST'])
@login_required
def admin_users():
    # Verifica se o usuário atual é um administrador
    if current_user.role != 'admin':
        abort(403)
    users = User.query.order_by(User.username.asc()).all()
    return render_template('admin_users.html', title='Administração de Usuários', users=users)

# Rota para mudar o papel de um usuário (apenas para administradores)
@app.route("/admin/change_role/<int:user_id>", methods=['POST'])
@login_required
def change_role(user_id):
    # Verifica se o usuário atual é um administrador
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    # Impede que um administrador altere o próprio papel
    if user.id == current_user.id:
        flash('Você não pode alterar seu próprio papel.', 'danger')
        return redirect(url_for('admin_users'))
    # Obtém o novo papel do formulário
    new_role = request.form.get('role')
    # Lista de papéis válidos
    valid_roles = ['user', 'moderator', 'admin']
    if new_role not in valid_roles:
        flash('Papel inválido.', 'danger')
        return redirect(url_for('admin_users'))
    # Atualiza o papel do usuário no banco de dados
    user.role = new_role
    db.session.commit()
    flash(f'O papel de {user.username} foi alterado para {new_role}.', 'success')
    return redirect(url_for('admin_users'))

# Rota para solicitar a redefinição de senha
@app.route("/reset_password", methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
        flash('Um e-mail foi enviado com instruções para redefinir sua senha.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Redefinir Senha', form=form)

# Função para enviar o e-mail de redefinição de senha
def send_reset_email(user):
    token = user.get_confirmation_token()
    msg = Message('Redefinição de Senha',
                  sender=os.environ.get('EMAIL_USER'),
                  recipients=[user.email])
    msg.body = f'''Para redefinir sua senha, visite o seguinte link:
{url_for('reset_token', token=token, _external=True)}

Se você não solicitou a redefinição de senha, por favor, ignore este e-mail.
'''
    mail.send(msg)

# Rota para redefinir a senha com um token
@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_confirmation_token(token)
    if user is None:
        flash('O token é inválido ou expirou.', 'danger')
        return redirect(url_for('reset_password_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Sua senha foi atualizada com sucesso! Você pode fazer login agora.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Redefinir Senha', form=form)

# Rota para buscar a citação assíncronamente
@app.route("/get_quote")
def get_quote():
    return jsonify(quote_of_the_day)
