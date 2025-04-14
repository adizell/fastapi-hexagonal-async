FROM python:3.10-slim-buster

# Definir variáveis de ambiente
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH='/' \
    LC_ALL=pt_BR.utf8 \
    LANG=pt_BR.utf8 \
    LANGUAGE=pt_BR.utf8 \
    TZ=America/Sao_Paulo \
    PATH="/root/.local/bin:$PATH"

# Definir fuso horário
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Instalar dependências básicas
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update -y && apt install -y \
    python3-pip \
    python3-venv \
    locales \
    tzdata \
    curl \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Configurar locale para pt_BR
RUN locale-gen pt_BR.UTF-8

# Copiar arquivos de dependências antes de instalar o Poetry
COPY pyproject.toml poetry.lock /app/

# Definir diretório de trabalho
WORKDIR /app

# Instalar Poetry e dependências do projeto
RUN curl -sSL https://install.python-poetry.org | python3 - && \
    poetry config virtualenvs.create false && \
    poetry install && \
    pip install uvicorn

# Copiar o arquivo .env para o container
COPY .env /app/.env

# Copiar o restante do código após instalar dependências
COPY ./app /app

# Excluir testes na imagem de produção
RUN rm -rf /app/test

# Definir o diretório de trabalho novamente, se necessário
WORKDIR /app

# CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--reload"]