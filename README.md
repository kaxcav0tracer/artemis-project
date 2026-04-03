<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=timeGradient&height=250&section=header&text=ARTEMIS%20SOAR&fontSize=55&fontAlignY=38&animation=fadeIn&fontColor=FFFFFF&desc=Automated%20Threat%20Intelligence%20Enrichment&descAlignY=58&descSize=20" width="100%" />

<br>

<img src="https://img.shields.io/badge/Version-2.1.0-blue?style=for-the-badge" alt="Version" />
<img src="https://img.shields.io/badge/GitLab-Pipeline_Passed-green?style=for-the-badge&logo=gitlab&logoColor=white" alt="Pipeline" />
<img src="https://img.shields.io/badge/Docker-Hardened-blueviolet?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" />
<img src="https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
<img src="https://img.shields.io/badge/PostgreSQL-Async-336791?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL" />
<img src="https://img.shields.io/badge/FortiGate-Automation-FF6600?style=for-the-badge&logo=fortinet&logoColor=white" alt="FortiGate" />

</div>

<br>

## 🛡️ Visão Geral

O **Artemis SOAR V2.1** é um motor de enriquecimento de alertas com cache de reputação e **ações automáticas**, projetado para automação de resposta a incidentes. Ele intercepta alertas do **Wazuh SIEM**, consulta o **VirusTotal** para inteligência de ameaças, persiste resultados em **PostgreSQL** e aplica **bloqueios automáticos no FortiGate** para ameaças críticas.

---

## 🏗️ Fluxo de Arquitetura

```mermaid
graph TD
    %% Define estilos SecOps
    classDef siem fill:#00A9E5,stroke:#fff,stroke-width:2px,color:#fff;
    classDef engine fill:#B084CC,stroke:#fff,stroke-width:2px,color:#fff;
    classDef vt fill:#C3E88D,stroke:#fff,stroke-width:2px,color:#000;
    classDef db fill:#336791,stroke:#fff,stroke-width:2px,color:#fff;
    classDef fg fill:#EE3124,stroke:#fff,stroke-width:2px,color:#fff;
    classDef block fill:#F07178,stroke:#000,stroke-width:3px,color:#000;
    classDef allow fill:#C3E88D,stroke:#000,stroke-width:3px,color:#000;

    A[Wazuh Webhook <br>Alerta IP] -->|Inicia Fluxo| B(Artemis Engine <br>FastAPI Async);
    B -->|Consulta IOC| DB[(PostgreSQL <br>Cache)];
    
    DB -- Cache Hit --> B;
    DB -- Cache Miss --> C{VirusTotal API};
    C -->|Retorna Score| DB;
    DB -->|Salva & Retorna| B;
    
    B -->|Avalia Score| D[Decision Matrix];
    D -->|Match Malicioso| E((BLOCK ACTION)):::block;
    D -->|Match Seguro| F((ALLOW ACTION)):::allow;
    
    E -->|API REST| FG[FortiGate Firewall <br>Blocklist Automático];

    %% Aplica estilos
    class A siem;
    class B engine;
    class C vt;
    class DB db;
    class FG fg;
```

---

## 🆕 V2.1 - Ações de Resposta Automática

### 🧱 FortiGate Integration
* **Bloqueio Automático:** IPs com `reputation_score ≥ 10` são automaticamente adicionados à lista de bloqueio do FortiGate.
* **Address Group:** Sincronização em tempo real com o grupo `Artemis_Blocklist`.
* **Resiliente:** Falhas na comunicação com o FortiGate não afetam o webhook (graceful degradation).
* **Auditoria:** Cada tentativa de bloqueio é registrada (sucesso/erro) no banco de dados.

### 🗄️ Cache de Reputação
* **PostgreSQL com SQLAlchemy Async** para persistência de dados.
* **Cache Hit:** Retorna verdicts em `<1ms` para IoCs já consultados.
* **Cache Miss:** Consulta VirusTotal apenas para novos IoCs.
* **Expiração Automática:** Cache válido por 24 horas.
* **Auditoria:** Histórico completo de decisões e timestamps.

### 🧩 Arquitetura Modular
* `models.py` - Modelos SQLAlchemy ORM (com colunas FortiGate).
* `config.py` - Configuração de conexão assíncrona.
* `database.py` - Gerenciamento de sessões.
* `integrations/fortigate.py` - Cliente FortiGate API async.
* `main.py` - Endpoints FastAPI com cache + resposta automática.

---

## 🛠️ Stack Tecnológica

<div align="center">
  <table border="0" style="background-color: transparent;">
    <tr>
      <td align="center" width="50%">
        <br>
        <a href="https://skillicons.dev">
          <img src="https://skillicons.dev/icons?i=python,fastapi,postgresql,docker,gitlab,linux&perline=3" alt="Stack" />
        </a>
        <br><br>
      </td>
      <td align="left" width="50%">
        <ul>
          <li><b>Framework:</b> FastAPI (Interface API de alta performance)</li>
          <li><b>Database:</b> PostgreSQL + SQLAlchemy (Cache Async)</li>
          <li><b>Driver Async:</b> asyncpg (Comunicação não-bloqueante)</li>
          <li><b>Threat Intel:</b> VirusTotal API</li>
          <li><b>Firewall (V2.1):</b> FortiGate REST API</li>
          <li><b>Runtime:</b> Docker (Hardened Multi-stage)</li>
        </ul>
      </td>
    </tr>
  </table>
</div>

---

## 🔒 Hardening e DevSecOps

Este projeto não foca apenas na funcionalidade, mas na **segurança em profundidade**:

* 🛡️ **Princípio do Menor Privilégio:** Container roda como `artemisuser` (não-root).
* 📦 **Imagens Multi-Stage:** Build otimizado para reduzir superfície de ataque.
* 🤖 **Esteira SAST:** Bandit analisa vulnerabilidades antes do deploy.
* 🔑 **Variáveis de Ambiente:** Chaves de API isoladas em tempo de execução.
* 💉 **ORM Seguro:** SQLAlchemy previne SQL injection via parameterized queries.
* 🌊 **Connection Pooling:** Pool de conexões async para evitar exhaustão.

---

## 🚀 Como Executar - V2

### Pré-requisitos
* Docker & Docker Compose (recomendado) ou PostgreSQL local
* Python 3.11+
* Chave de API do VirusTotal

### Opção 1: Docker Compose (Recomendado)
```bash
# 1. Copiar e configurar variáveis de ambiente
cp .env.example .env
# Editar .env com sua VT_API_KEY e configs do FortiGate

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
   - Acesse: `Firewall → Addresses → Address Groups`
   - Crie novo grupo: `Artemis_Blocklist`
   - Tipo: `Firewall Address`

2. **Gerar API Token:**
   - Acesse: `System → Administrators`
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
FG_URL=[https://192.168.1.1](https://192.168.1.1)

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

# 3. Verificar no banco de dados
psql -U postgres -d artemis -h localhost
SELECT ioc_value, reputation_score, fortigate_synced, fortigate_response 
FROM threat_cache 
WHERE ioc_value = '203.0.113.45';
```

---

## 🗄️ Banco de Dados - Schema

### Tabela: `threat_cache`
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
```
*A segunda resposta deve ter `"cached": true` e tempo de resposta <1ms.*

---

## 📦 Variáveis de Ambiente

Copiar `.env.example` para `.env` e preencher:

* `VT_API_KEY` - Chave da API VirusTotal (obrigatória)
* `DATABASE_URL` - URL de conexão PostgreSQL (padrão: localhost)
* `SQL_ECHO` - Ativar log de queries SQL (true/false, padrão: false)

---

## 🤝 Contribuições

Contribuições são bem-vindas! Para modificações maiores, abra uma issue primeiro para discussão.

---

<div align="center">
  <p><i>Desenvolvido como parte do arsenal de defesa de <b>Victor Girardi</b></i></p>
  
  <a href="https://linkedin.com/in/victor-ramalho-lisboa" target="_blank">
    <img src="https://img.shields.io/badge/LinkedIn-Profile-0A66C2?style=flat-square&logo=linkedin&logoColor=white" alt="LinkedIn" />
  </a>
</div>

<div align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=timeGradient&height=100&section=footer" width="100%" />
</div>


