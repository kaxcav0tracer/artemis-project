# 🛡️ Artemis SOAR - Threat Intelligence Integration

![Version](https://img.shields.io/badge/Version-2.1.0-blue?style=for-the-badge)
![GitLab Pipeline](https://img.shields.io/badge/GitLab-Pipeline--Passed-green?style=for-the-badge&logo=gitlab)
![Docker](https://img.shields.io/badge/Docker-Hardened-blue?style=for-the-badge&logo=docker)
![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Async-336791?style=for-the-badge&logo=postgresql)
![FortiGate](https://img.shields.io/badge/FortiGate-Automation-FF6600?style=for-the-badge&logo=fortinet)

**Artemis SOAR V2.1** é um motor de enriquecimento de alertas com cache de reputação e **ações automáticas**, projetado para automação de resposta a incidentes. Ele intercepta alertas do **Wazuh SIEM**, consulta o **VirusTotal** para inteligência de ameaças, persiste resultados em **PostgreSQL** e aplica **bloqueios automáticos no FortiGate** para ameaças críticas.

---

## 🆕 V2.1 - Ações de Resposta Automática

### FortiGate Integration
- **Bloqueio Automático:** IPs com reputation_score ≥ 10 são automaticamente adicionados à lista de bloqueio do FortiGate
- **Address Group:** Sincronização em tempo real com o grupo 'Artemis_Blocklist'
- **Resiliente:** Falhas na comunicação com FortiGate não afetam o webhook (graceful degradation)
- **Auditoria:** Cada tentativa de bloqueio é registrada (sucesso/erro) no banco de dados

### Cache de Reputação
- **PostgreSQL com SQLAlchemy Async** para persistência de dados
- **Cache Hit:** Retorna verdicts em <1ms para IoCs já consultados
- **Cache Miss:** Consulta VirusTotal apenas para novos IoCs
- **Expiração Automática:** Cache válido por 24 horas
- **Auditoria:** Histórico completo de decisões e timestamps

### Arquitetura Modular
- `models.py` - Modelos SQLAlchemy ORM (com colunas FortiGate)
- `config.py` - Configuração de conexão assíncrona
- `database.py` - Gerenciamento de sessões
- `integrations/fortigate.py` - Cliente FortiGate API async
- `main.py` - Endpoints FastAPI com cache + resposta automática

---

## 🛠️ Stack Tecnológica

| Componente | Tecnologia | Papel no Projeto |
| :--- | :--- | :--- |
| **Framework** | FastAPI | Interface de API de alta performance e assíncrona |
| **Database** | PostgreSQL + SQLAlchemy | Persistência de cache de reputação com ORM async |
| **Driver Async** | asyncpg | Comunicação não-bloqueante com PostgreSQL |
| **Threat Intel** | VirusTotal API | Análise de IPs, Hashes e domínios maliciosos |
| **Firewall (V2.1)** | FortiGate REST API | Bloqueio automático de IPs maliciosos |
| **HTTP Async** | httpx | Cliente HTTP assíncrono para APIs externas |
| **Runtime** | Docker | Containerização multi-stage com hardening |
| **Segurança** | Bandit (SAST) | Análise estática de código para vulnerabilidades |
| **CI/CD** | GitLab CI | Pipeline automatizado com gates de segurança |

---

## 🔒 Hardening e DevSecOps

Este projeto não foca apenas na funcionalidade, mas na **segurança em profundidade**:

* **Princípio do Menor Privilégio:** Container roda como `artemisuser` (não-root)
* **Imagens Multi-Stage:** Build otimizado para reduzir superfície de ataque
* **Esteira SAST:** Bandit analisa vulnerabilidades antes do deploy
* **Variáveis de Ambiente:** Chaves de API isoladas em tempo de execução
* **ORM Seguro:** SQLAlchemy prevent SQL injection via parameterized queries
* **Connection Pooling:** Pool de conexões async para evitar exhaustão

---

## 🚀 Como Executar - V2

### Pré-requisitos
- Docker & Docker Compose (recomendado) ou PostgreSQL local
- Python 3.11+
- Chave de API do VirusTotal

### Opção 1: Docker Compose (Recomendado)
```bash
# 1. Copiar e configurar variáveis de ambiente
cp .env.example .env
# Editar .env com sua VT_API_KEY

# 2. Subir PostgreSQL + Artemis
docker-compose up -d

# 3. API disponível em http://localhost:8000
```

### Opção 2: Docker Manual
```bash
# 1. Subir PostgreSQL
docker run -d \
  --name artemis-db \
  -e POSTGRES_PASSWORD=artemis \
  -p 5432:5432 \
  postgres:15

# 2. Construir imagem
docker build -t artemis:v2 .

# 3. Executar container
docker run -p 8000:8000 \
  -e VT_API_KEY="sua_chave_aqui" \
  -e DATABASE_URL="postgresql+asyncpg://postgres:artemis@host.docker.internal:5432/artemis" \
  artemis:v2
```

### Opção 3: Desenvolvimento Local
```bash
# 1. Criar ambiente virtual
python -m venv venv
source venv/bin/activate  # ou venv\Scripts\activate no Windows

# 2. Instalar dependências
pip install -r requirements.txt

# 3. Configurar variáveis de ambiente
cp .env.example .env
# Editar .env

# 4. Executar aplicação
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```

---

## 📋 Endpoints

### GET `/`
Health check da aplicação.
```bash
curl http://localhost:8000/
```
**Response:** `{"status": "ok"}`

### POST `/webhook/wazuh`
Recebe alertas do Wazuh, verifica cache e retorna verdicts.

**Request:**
```json
{
  "data": {
    "srcip": "192.168.1.100"
  }
}
```

**Response (Cache Hit):**
```json
{
  "action": "ALLOW",
  "source_ip": "192.168.1.100",
  "reputation_score": 0,
  "cached": true,
  "cache_hit_at": "2024-04-03T10:30:00+00:00",
  "expires_at": "2024-04-04T10:30:00+00:00"
}
```

**Response (Cache Miss + VT Query + FortiGate Blocked):**
```json
{
  "action": "BLOCK",
  "source_ip": "203.0.113.45",
  "reputation_score": 15,
  "cached": false,
  "expires_at": "2024-04-04T10:40:00+00:00",
  "fortigate": {
    "status": "blocked",
    "message": "IP 203.0.113.45 added to Artemis_Blocklist",
    "error": null
  },
  "virustotal": { ... }
}
```

**Response (Cache Hit - Already Blocked):**
```json
{
  "action": "BLOCK",
  "source_ip": "203.0.113.45",
  "reputation_score": 15,
  "cached": true,
  "cache_hit_at": "2024-04-03T10:40:00+00:00",
  "expires_at": "2024-04-04T10:40:00+00:00",
  "fortigate": {
    "status": "skipped",
    "message": "IP already in blocklist (cached)",
    "error": null
  }
}
```

---

## ⚙️ Configuração FortiGate (V2.1)

### Pré-requisitos FortiGate
1. **Criar o Address Group:**
   - Acesse: Firewall → Addresses → Address Groups
   - Crie novo grupo: `Artemis_Blocklist`
   - Tipo: `Firewall Address`

2. **Gerar API Token:**
   - Acesse: System → Administrators
   - Crie novo API User com permissões de escrita em Firewall
   - Copie o token para `FG_API_TOKEN`

3. **Configurar Firewall Policy:**
   - Crie política de negação para o grupo `Artemis_Blocklist`
   - Exemplo: Nega tráfego incoming quando source in `Artemis_Blocklist`

### Configuração no Artemis

**1. Copiar e editar `.env`:**
```bash
cp .env.example .env
```

**2. Editar `.env` com valores FortiGate:**
```bash
# Ativar integração FortiGate
FG_ENABLED=true

# URL de gerenciamento do FortiGate
FG_URL=https://192.168.1.1

# Token API do FortiGate
FG_API_TOKEN=seu_token_api_aqui
```

**3. Reiniciar Artemis:**
```bash
docker-compose restart artemis
# ou
# uvicorn src.main:app --reload
```

### Validar Integração

```bash
# 1. Verificar logs
docker-compose logs artemis | grep -i fortigate

# 2. Enviar um alerta com alta reputação
curl -X POST http://localhost:8000/webhook/wazuh \
  -H "Content-Type: application/json" \
  -d '{"data": {"srcip": "203.0.113.45"}}'

# 3. Verificar resposta inclui seção fortigate
# 4. Verificar no FortiGate se IP foi adicionado à lista

# 5. Consultar banco de dados
psql -U postgres -d artemis -h localhost
SELECT ioc_value, reputation_score, fortigate_synced, fortigate_response, fortigate_sync_error
FROM threat_cache
WHERE ioc_value = '203.0.113.45';
```

---

## 🗄️ Banco de Dados - Schema

### Tabela: threat_cache
```sql
CREATE TABLE threat_cache (
    ioc_value VARCHAR(255) PRIMARY KEY,
    ioc_type VARCHAR(50) NOT NULL DEFAULT 'IP',
    reputation_score INTEGER NOT NULL DEFAULT 0,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL INDEX,
    action_taken VARCHAR(50) NOT NULL DEFAULT 'ALLOW',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);
```

---

## 🧪 Testes

### Teste Local de Cache Hit/Miss
```bash
# Terminal 1: Iniciar aplicação
uvicorn src.main:app --reload

# Terminal 2: Primeira chamada (CACHE MISS)
curl -X POST http://localhost:8000/webhook/wazuh \
  -H "Content-Type: application/json" \
  -d '{"data": {"srcip": "8.8.8.8"}}'

# Aguardar 1-2 segundos, depois segunda chamada (CACHE HIT)
curl -X POST http://localhost:8000/webhook/wazuh \
  -H "Content-Type: application/json" \
  -d '{"data": {"srcip": "8.8.8.8"}}'

# Segunda resposta deve ter "cached": true e tempo de resposta <1ms
```

### Verificar Cache no PostgreSQL
```bash
psql -U postgres -d artemis -h localhost
SELECT * FROM threat_cache;
```

---

## 📦 Variáveis de Ambiente

Copiar `.env.example` para `.env` e preencher:

- `VT_API_KEY` - Chave da API VirusTotal (obrigatória)
- `DATABASE_URL` - URL de conexão PostgreSQL (padrão: localhost)
- `SQL_ECHO` - Ativar log de queries SQL (true/false, padrão: false)

---

## 🔄 Fluxo de Funcionamento V2

```
┌─────────────────────┐
│  Alerta Wazuh       │
│  (IP: 192.168.x.x)  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────────────┐
│ Artemis SOAR Webhook        │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────────────┐
│ 1. Check Cache (PostgreSQL)         │
│    - IOC exists?                    │
│    - Not expired?                   │
└──────────┬──────────────────────────┘
           │
      Yes  │  No
           │
    ┌──────▼──────┐
    │ CACHE HIT   │  ◄─────────┐
    │ Return      │          ┌─┴─────────────────────┐
    │ Verdict     │          │ 2. Call VirusTotal    │
    └──────┬──────┘          │    (CACHE MISS)       │
           │                 └─────────┬─────────────┘
           │                           │
           │                           ▼
           │                ┌──────────────────────┐
           │                │ 3. Get Reputation    │
           │                │    Score             │
           │                └─────────┬────────────┘
           │                          │
           │                          ▼
           │                ┌────────────────────┐
           │                │ 4. Determine Action │
           │                │    (BLOCK/ALLOW)    │
           │                └─────────┬───────────┘
           │                          │
           │                          ▼
           │                ┌──────────────────────┐
           │                │ 5. Save to Cache     │
           │                │    (Expires: 24h)    │
           │                └─────────┬────────────┘
           │                          │
           └──────────┬───────────────┘
                      │
                      ▼
         ┌────────────────────────┐
         │ Return Verdict + Data  │
         │ {"action": "BLOCK"...} │
         └────────────────────────┘
```

---

## 🤝 Contribuições

Contribuições são bem-vindas! Para modificações maiores, abra uma issue primeiro para discussão.

---

Desenvolvido por **Victor Ramalho** como um laboratório prático de Engenharia DevSecOps e Threat Intelligence.

**V1:** Initial release - Stateless VirusTotal integration
**V2:** Cache de reputação com PostgreSQL + SQLAlchemy Async
**V2.1:** Ações de resposta automática com FortiGate integration