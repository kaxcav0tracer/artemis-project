import os
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException

app = FastAPI(title="Artemis SOAR")


@app.get("/")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/webhook/wazuh")
async def wazuh_webhook(payload: dict[str, Any]) -> dict[str, Any]:
    source_ip = payload.get("data", {}).get("srcip")
    if not source_ip:
        raise HTTPException(status_code=400, detail="Missing data.srcip in payload")

    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="VT_API_KEY is not configured")

    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{source_ip}"
    headers = {
        "x-apikey": api_key,
        "accept": "application/json",
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(vt_url, headers=headers)
        response.raise_for_status()

    vt_data = response.json()
    malicious_count = (
        vt_data.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
        .get("malicious", 0)
    )

    action = "BLOCK" if malicious_count >= 3 else "ALLOW"
    return {
        "action": action,
        "source_ip": source_ip,
        "malicious": malicious_count,
        "virustotal": vt_data,
    }
