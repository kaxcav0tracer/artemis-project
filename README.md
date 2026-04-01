<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=timeGradient&height=250&section=header&text=ARTEMIS%20SOAR&fontSize=55&fontAlignY=38&animation=fadeIn&fontColor=FFFFFF&desc=Automated%20Threat%20Intelligence%20Enrichment&descAlignY=58&descSize=20" width="100%" />

<br>

<img src="https://img.shields.io/badge/Status-Stable-success?style=for-the-badge&logo=checkmarx&logoColor=white" alt="Status" />
<img src="https://img.shields.io/badge/SecOps-Pipeline_Passed-blueviolet?style=for-the-badge&logo=gitlab&logoColor=white" alt="Pipeline" />
<img src="https://img.shields.io/badge/Security-SAST_Audited-green?style=for-the-badge&logo=bandit&logoColor=white" alt="Security" />

</div>

<br>

## 🛡️ Visão Geral

O **Artemis SOAR** é um microserviço de alta performance projetado para orquestração de segurança e enriquecimento de ameaças. Ele atua como uma camada de inteligência intermediária que intercepta e analisa logs do **Wazuh SIEM**, consultando a reputação de artefatos (IPs, Hashes) na API do **VirusTotal** para automatizar a tomada de decisão no SOC.

---

## 🏗️ Fluxo de Arquitetura (Mermaid.js)

O GitHub suporta nativamente diagramas de arquitetura bonitões. Este diagrama mostra o fluxo exato que você construiu:

```mermaid
graph TD
    %% Define estilos SecOps
    classDef siem fill:#00A9E5,stroke:#fff,stroke-width:2px,color:#fff;
    classDef engine fill:#B084CC,stroke:#fff,stroke-width:2px,color:#fff;
    classDef vt fill:#C3E88D,stroke:#fff,stroke-width:2px,color:#fff;
    classDef block fill:#F07178,stroke:#000,stroke-width:3px,color:#000;
    classDef allow fill:#C3E88D,stroke:#000,stroke-width:3px,color:#000;

    A[SIEM Alerta <br>ex: WazuhWebhook] -->|Inicia Fluxo| B(Artemis Engine <br>FastAPI Async);
    B -->|Check IP/Hash| C{VirusTotal API <br>HTTPX};
    C -->|Retorna Score| B;
    B -->|Avalia Score| D[Decision Matrix];
    D -->|Match Malicioso| E((BLOCK ACTION)):::block;
    D -->|Match Seguro| F((ALLOW ACTION)):::allow;

    %% Aplica estilos
    class A siem;
    class B engine;
    class C vt;
```

---

## 🌌 Engenharia do Projeto & Stack

Tabelas HTML invisíveis são o segredo para esse layout de "Tabela Invisível" que você já gosta.

<div align="center">
  <table border="0" style="background-color: transparent;">
    <tr>
      <td align="left" width="55%">
        <h3> ⚡ Core Capabilities </h3>
        <ul>
          <li><b>Async Engine:</b> Construído com FastAPI e HTTPX para processamento não-bloqueante e de alta performance.</li>
          <li><b>Smart Enrichment:</b> Filtra, normaliza e correlaciona dados brutos do SIEM em inteligência tática.</li>
          <li><b>Decision Matrix:</b> Gera vereditos automáticos baseados em scores de reputação personalizáveis.</li>
        </ul>
      </td>
      <td align="center" width="45%">
        <h3> 🛠️ Arsenal Tecnológico </h3>
        <a href="https://skillicons.dev">
          <img src="https://skillicons.dev/icons?i=python,docker,gitlab,linux,fastapi&perline=3" alt="Stack" />
        </a>
      </td>
    </tr>
  </table>
</div>

<br>

## 🔒 Defense in Depth & Hardening (DevSecOps)

Ao contrário de scripts simples, a Artemis foi projetada sob princípios rigorosos de segurança de infraestrutura:

* 🛡️ **Princípio do Menor Privilégio:** O container é configurado para rodar sob um usuário restrito (`artemisuser`). O processo da API nunca roda como `root`.
* 📦 **Multi-stage build:** A imagem final Docker é otimizada, reduzindo a superfície de ataque ao remover todas as ferramentas de compilação da imagem final.
* 🤖 **Automated SAST:** Pipeline integrada no GitLab que utiliza o **Bandit** para varredura estática, garantindo 0 falhas críticas no código fonte.

---

## 🚀 Deployment & Lab

Unifiquei os blocos de código para ficar mais limpo.

### 🐋 Docker Orchestration

```bash
# 1. Build da imagem Docker blindada e otimizada
docker build -t artemis-soar:latest .

# 2. Deploy com injeção de segredos via ENV
# Lembre-se de substituir 'your_api_key_here' pela sua chave real
docker run -d -p 8000:8000 \
  --name artemis-engine \
  -e VT_API_KEY="your_api_key_here" \
  artemis-soar:latest
```

---

<div align="center">
  <h3> 🔮 Pipeline Insights </h3>
  <img src="https://github-readme-stats.vercel.app/api/pin/?username=kaxcav0tracer&repo=artemis-project&theme=transparent&title_color=B084CC&text_color=A8B2C3&icon_color=00F5FF&hide_border=true" alt="Repo Stats" />
  
  <br><br>
  
  <p><i>Desenvolvido como parte do arsenal de defesa de **Victor Ramalho**</i></p>
  
  <a href="https://linkedin.com/in/victor-ramalho-lisboa" target="_blank">
    <img src="https://img.shields.io/badge/LinkedIn-Profile-0A66C2?style=flat-square&logo=linkedin&logoColor=white" alt="LinkedIn" />
  </a>
</div>

<div align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=timeGradient&height=100&section=footer" width="100%" />
</div>
