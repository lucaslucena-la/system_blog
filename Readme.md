# 📘 System Blog  

Um sistema de blog desenvolvido com **Flask**, com suporte a registro, autenticação, gerenciamento de posts, papéis de usuário (Padrão, Moderador, Administrador) e envio de e-mails de confirmação/reset de senha.  

---

##  Tecnologias Utilizadas  

- **Backend:** [Flask](https://flask.palletsprojects.com/) (Python)  
- **Banco de Dados:** SQLite (padrão, mas pode ser trocado por PostgreSQL/MySQL facilmente)  
- **ORM:** SQLAlchemy  
- **Autenticação:** Flask-Login + Bcrypt  
- **Templates:** Jinja2 + HTML5 + CSS3  
- **Estilos:** Bootstrap 4 + estilos customizados (CSS modular por página)  
- **E-mails:** Flask-Mail (SMTP via Gmail)  
- **Gerenciamento de Papéis:** Sistema de Roles (User, Moderador, Admin)  
- **Containerização:** Docker + Docker Compose  

---

## ⚙️ Funcionalidades  

✅ Registro de usuários com confirmação por e-mail  
✅ Login com redirecionamento por papéis  
✅ Perfis com upload de imagem  
✅ CRUD de posts (criar, editar e excluir)  
✅ Controle de permissões:  
- **Usuário Padrão:** pode gerenciar apenas seus posts  
- **Moderador:** pode excluir qualquer post  
- **Administrador:** além das permissões de moderador, pode alterar papéis de usuários  
✅ Dashboard específico para cada papel  
✅ Sistema de alertas (mensagens flash)  
✅ API assíncrona para "Citação do Dia" (com tradução)

## Pré-requisitos

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) instalado e rodando
- [Git](https://git-scm.com/)  
- [Python 3.10+](https://www.python.org/downloads/)  
- **Pip** (gerenciador de pacotes do Python)  
- **Virtualenv** (opcional, mas recomendado para ambientes isolados) 

## 🐳 Rodando com Docker

### 1. Clonar o repositório  
```bash
git clone https://github.com/seu-usuario/system-blog.git
cd system-blog
```
### 1. Buildar e subir o container
```bash
docker-compose up --build
```
Este comando irá criar o banco no docker, as roles e também as seedings inicias:
 - Email: admin@systemblog.com | senha: admin123
 - Email: moderador@systemblog.com | senha: moderador123


3. Acessar a aplicação
👉 http://localhost:5000

---

## 🛠️ Como Rodar Localmente  
### 1. Clonar o repositório  
```bash
git clone https://github.com/seu-usuario/system-blog.git
cd system-blog
```

### 2. Criar o ambiente Virtual
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate
```
### 3. Instalar as Dependências
```bash
pip install -r requirements.txt
```
### 4. Configurar variáveis de ambiente
Crie um arquivo .env ou configure diretamente no terminal:
```bash
set SECRET_KEY=uma_chave_segura
set EMAIL_USER=seuemail@gmail.com
set EMAIL_PASS=sua_senha_de_app
set MAIL_DEFAULT_SENDER=seuemail@gmail.com
```
A senha deve ser uma senha de app gerada no Gmail, não a senha normal da conta.

### 5. Criar banco de dados e roles iniciais

```bash
python seed_roles.py
```
Isso criará os papéis:

 - Padrão (User)
 - Moderador
 - Administrador

E também criara seedings inicias ficticias:
 - Email: admin@systemblog.com | senha: admin123
 - moderador@systemblog.com | senha: moderador123

### 6. rodar o servidor
```bash
flask run
```
O app estará disponível em:
http://127.0.0.1:5000


