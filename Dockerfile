# Imagem base
FROM python:3.11-slim

# Diretório de trabalho
WORKDIR /app

# Dependências
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia o restante da aplicação
COPY . .

# Expondo a porta do Flask
EXPOSE 5000

# Variáveis do Flask
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

# Script de entrada que cria DB + seeds e inicia o servidor
ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
