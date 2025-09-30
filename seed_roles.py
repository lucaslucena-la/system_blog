from app import app, db, bcrypt
from models import Role, User

with app.app_context():
    db.create_all()

    # --- Roles ---
    roles_by_name = {r.name: r for r in Role.query.all()}
    need_commit = False

    def ensure_role(id_, name, can_moderate, can_admin):
        global roles_by_name, need_commit
        r = Role.query.filter_by(name=name).first()
        if not r:
            r = Role(id=id_, name=name, can_moderate=can_moderate, can_admin=can_admin)
            db.session.add(r)
            need_commit = True
        roles_by_name[name] = r

    ensure_role(1, "User",        False, False)
    ensure_role(2, "Moderador",    True,  False)
    ensure_role(3, "Administrador",True,  True)

    if need_commit:
        db.session.commit()
        print(" Roles criados/garantidos.")

    # --- Admin  ---
    admin_email = "admin@systemblog.com"
    admin = User.query.filter_by(email=admin_email).first()
    if not admin:
        admin = User(
            username="admin",
            email=admin_email,
            password=bcrypt.generate_password_hash("admin123").decode("utf-8"),
            role=roles_by_name["Administrador"],
            is_active=True
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin criado: admin@systemblog.com | senha: admin123")