# seed_roles.py
from app import app, db
from models import Role

with app.app_context():
    roles = [
        {"name": "User", "can_moderate": False, "can_admin": False},
        {"name": "Moderator", "can_moderate": True, "can_admin": False},
        {"name": "Admin", "can_moderate": True, "can_admin": True},
    ]

    for role_data in roles:
        role = Role.query.filter_by(name=role_data["name"]).first()
        if not role:
            role = Role(**role_data)
            db.session.add(role)
    
    db.session.commit()
    print("✅ Papéis criados/atualizados com sucesso!")
