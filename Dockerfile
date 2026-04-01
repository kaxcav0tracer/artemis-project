# ESTÁGIO 1: Compilação (Build)
FROM python:3.11-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# ESTÁGIO 2: Execução (Runtime - O Cofre Slim)
FROM python:3.11-slim
WORKDIR /app

# 1. Cria usuário e grupo de sistema no Debian/Slim
RUN groupadd -r artemisgroup && useradd -r -g artemisgroup -m artemisuser

# 2. Copia as bibliotecas compiladas na mesma arquitetura
COPY --from=builder --chown=artemisuser:artemisgroup /root/.local /home/artemisuser/.local

# 3. Copia o código da API
COPY --chown=artemisuser:artemisgroup src/ /app/src/

# 4. Atualiza o PATH
ENV PATH=/home/artemisuser/.local/bin:$PATH

# 5. Trava o cofre no usuário sem privilégios
USER artemisuser

EXPOSE 8000
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]