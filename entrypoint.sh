#!/bin/sh
set -e

# Cria o banco (tabelas) e aplica seeds (idempotente)
python seed_roles.py

# Sobe o Flask
exec flask run --host=0.0.0.0
