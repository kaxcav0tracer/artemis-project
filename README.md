# 🛡️ Artemis SOAR - Threat Intelligence Integration

![GitLab Pipeline](https://img.shields.io/badge/GitLab-Pipeline--Passed-green?style=for-the-badge&logo=gitlab)
![Docker](https://img.shields.io/badge/Docker-Hardened-blue?style=for-the-badge&logo=docker)
![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)

**Artemis SOAR** é um motor de enriquecimento de alertas projetado para automação de resposta a incidentes. Ele intercepta alertas do **Wazuh SIEM** e utiliza a inteligência do **VirusTotal** para determinar ações de bloqueio em tempo real.

---

## 🛠️ Stack Tecnológica

| Componente | Tecnologia | Papel no Projeto |
| :--- | :--- | :--- |
| **Framework** | FastAPI | Interface de API de alta performance e assíncrona. |
| **Runtime** | Docker | Containerização isolada para segurança e portabilidade. |
| **Segurança** | Bandit (SAST) | Análise estática de código para detecção de falhas. |
| **Automação** | GitLab CI/CD | Esteira de integração contínua e automação de segurança. |

---

## 🔒 Hardening e DevSecOps

Este projeto não foca apenas na funcionalidade, mas na **segurança da infraestrutura**:

* **Princípio do Menor Privilégio:** O container roda com um usuário comum (`artemisuser`), impedindo acesso `root` ao host.
* **Imagens Multi-Stage:** Build otimizado para reduzir a superfície de ataque.
* **Esteira de Segurança (SAST):** Pipeline que impede o deploy de código com vulnerabilidades via **Bandit**.
* **Comunicação Blindada:** Uso de variáveis de ambiente para chaves de API.

---

## 🚀 Como Executar

### Build e Run
```bash
# 1. Construir a imagem Docker blindada
docker build -t artemis:v1 .

# 2. Subir o container passando a chave de API
docker run -p 8000:8000 -e VT_API_KEY="SUA_CHAVE_AQUI" artemis:v1

Desenvolvido por Victor Ramalho como um laboratório prático de Engenharia DevSecOps.