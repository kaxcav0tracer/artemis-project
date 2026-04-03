import os
from typing import Any, AsyncGenerator
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException
from sqlalchemy import select

from .database import init_db, close_db
from .config import async_session_maker
from .models import ThreatCache
from .integrations.fortigate import FortiGateAPI

# Global FortiGate client (initialized on startup if enabled)
fortigate_client: FortiGateAPI | None = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """FastAPI lifespan context manager for startup and shutdown events"""
    global fortigate_client

    # === STARTUP ===
    # Initialize database tables
    await init_db()

    # Initialize FortiGate API client if enabled
    fg_enabled = os.getenv("FG_ENABLED", "false").lower() == "true"
    if fg_enabled:
        fg_url = os.getenv("FG_URL")
        fg_api_token = os.getenv("FG_API_TOKEN")

        if fg_url and fg_api_token:
            fortigate_client = FortiGateAPI(fg_url=fg_url, fg_api_token=fg_api_token)
            print(f"✓ FortiGate integration enabled: {fg_url}")
        else:
            print("⚠ FortiGate enabled but FG_URL or FG_API_TOKEN not configured")

    yield

    # === SHUTDOWN ===
    # Clean up database connections
    await close_db()


app = FastAPI(title="Artemis SOAR", version="2.1.0", lifespan=lifespan)


@app.get("/")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


async def _call_virustotal(source_ip: str, api_key: str) -> dict[str, Any]:
    """Call VirusTotal API to get threat intelligence

    Args:
        source_ip: IP address to query
        api_key: VirusTotal API key

    Returns:
        Response dict with keys:
            - 'success': bool indicating if API call succeeded
            - 'data': VirusTotal data if successful, dict with fallback values if failed
            - 'error': Error message if failed
            - 'status_code': HTTP status code if failed
    """
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{source_ip}"
    headers = {
        "x-apikey": api_key,
        "accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:  # nosec
            response = await client.get(vt_url, headers=headers)

            if response.status_code == 401:
                print(f"⚠ VirusTotal 401 Unauthorized for IP {source_ip} - using fallback values")
                return {
                    "success": False,
                    "status_code": 401,
                    "error": "VirusTotal API key unauthorized or inactive",
                    "data": {
                        "data": {
                            "attributes": {
                                "last_analysis_stats": {"malicious": 5}
                            }
                        }
                    },
                }

            response.raise_for_status()
            return {
                "success": True,
                "status_code": response.status_code,
                "data": response.json(),
            }

    except httpx.HTTPStatusError as e:
        print(f"⚠ VirusTotal HTTP {e.response.status_code} for IP {source_ip} - using fallback values")
        return {
            "success": False,
            "status_code": e.response.status_code,
            "error": f"VirusTotal API HTTP {e.response.status_code}",
            "data": {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 5}
                    }
                }
            },
        }
    except httpx.RequestError as e:
        print(f"⚠ VirusTotal connection error for IP {source_ip}: {str(e)} - using fallback values")
        return {
            "success": False,
            "status_code": 0,
            "error": f"VirusTotal connection error: {str(e)}",
            "data": {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 5}
                    }
                }
            },
        }
    except Exception as e:
        print(f"⚠ Unexpected error calling VirusTotal for IP {source_ip}: {str(e)} - using fallback values")
        return {
            "success": False,
            "status_code": 0,
            "error": f"Unexpected VirusTotal error: {str(e)}",
            "data": {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 5}
                    }
                }
            },
        }


@app.post("/webhook/wazuh")
async def wazuh_webhook(payload: dict[str, Any]) -> dict[str, Any]:
    """Receive and process Wazuh security alerts with threat intelligence

    Flow:
    1. Extract IOC value from payload
    2. Check cache for existing reputation (Hit → Return cached result)
    3. If not cached or expired, query VirusTotal API (Miss → Call VT)
    4. Save/update cache with 24h expiration
    5. Return verdict with action taken

    Args:
        payload: Wazuh webhook payload containing source IP

    Returns:
        Decision object with action (BLOCK/ALLOW) and reputation data
    """
    # Extract IOC value from payload
    source_ip = payload.get("data", {}).get("srcip")
    if not source_ip:
        raise HTTPException(status_code=400, detail="Missing data.srcip in payload")

    # Validate API key configuration
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="VT_API_KEY is not configured")

    # Open async database session
    async with async_session_maker() as session:
        # === STEP 1: Check cache (CACHE HIT path) ===
        stmt = select(ThreatCache).where(ThreatCache.ioc_value == source_ip)
        result = await session.execute(stmt)
        cache_record = result.scalars().first()

        # If cache hit and not expired, return immediately
        if (
            cache_record
            and cache_record.expires_at > datetime.now(timezone.utc)  # type: ignore
        ):
            # Build FortiGate status for cache hit
            fortigate_status = None
            if cache_record.reputation_score >= 10:  # type: ignore
                if cache_record.fortigate_synced:  # type: ignore
                    fortigate_status = {
                        "status": "skipped",
                        "message": "IP already in blocklist (cached)",
                        "error": None,
                    }
                elif cache_record.fortigate_sync_error:  # type: ignore
                    fortigate_status = {
                        "status": "failed",
                        "message": "Previous FortiGate sync failed",
                        "error": cache_record.fortigate_sync_error,
                    }

            response_data = {
                "action": cache_record.action_taken,
                "source_ip": source_ip,
                "reputation_score": cache_record.reputation_score,
                "cached": True,
                "cache_hit_at": cache_record.last_seen.isoformat(),
                "expires_at": cache_record.expires_at.isoformat(),
            }

            if fortigate_status:
                response_data["fortigate"] = fortigate_status

            return response_data

        # === STEP 2: Cache miss or expired → Call VirusTotal API ===
        vt_response = await _call_virustotal(source_ip, api_key)
        vt_data = vt_response["data"]

        # Check if VT call succeeded; if not, use fallback values
        vt_call_failed = not vt_response.get("success", True)
        vt_error_message = vt_response.get("error", "Unknown error") if vt_call_failed else None

        # Extract malicious vendor count from VirusTotal response (or fallback)
        malicious_count = (
            vt_data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
            .get("malicious", 0)
        )

        # Determine action based on malicious count
        action = "BLOCK" if malicious_count >= 3 else "ALLOW"

        # === STEP 3: Apply FortiGate blocking if high reputation threat ===
        fortigate_status = None
        fg_blocked = False
        fg_error = None

        if malicious_count >= 10 and fortigate_client:
            # High reputation threat and FortiGate is enabled
            fg_response = await fortigate_client.block_ip(source_ip)

            if fg_response["success"]:
                fg_blocked = True
                fortigate_status = {
                    "status": "blocked",
                    "message": fg_response["message"],
                    "error": None,
                }
            else:
                # FortiGate error but don't fail the webhook
                fg_error = fg_response.get("error", "Unknown error")
                fortigate_status = {
                    "status": "failed",
                    "message": fg_response["message"],
                    "error": fg_error,
                }
        elif malicious_count >= 10 and not fortigate_client:
            # High reputation threat but FortiGate disabled
            fortigate_status = {
                "status": "skipped",
                "message": "FortiGate integration not enabled",
                "error": None,
            }

        # === STEP 4: Save or update cache with 24h expiration ===
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=24)

        # Create or update cache entry
        if cache_record:
            # Update existing record
            cache_record.reputation_score = malicious_count  # type: ignore
            cache_record.action_taken = action  # type: ignore
            cache_record.last_seen = now  # type: ignore
            cache_record.expires_at = expires_at  # type: ignore
            cache_record.updated_at = now  # type: ignore
            if fg_blocked:
                cache_record.fortigate_synced = True  # type: ignore
                cache_record.fortigate_response = "blocked_on_firewall"  # type: ignore
                cache_record.fortigate_sync_error = None  # type: ignore
            elif fg_error:
                cache_record.fortigate_synced = False  # type: ignore
                cache_record.fortigate_response = None  # type: ignore
                cache_record.fortigate_sync_error = fg_error  # type: ignore
        else:
            # Create new record
            cache_record = ThreatCache(
                ioc_value=source_ip,
                ioc_type="IP",
                reputation_score=malicious_count,
                last_seen=now,
                expires_at=expires_at,
                action_taken=action,
                fortigate_synced=fg_blocked,
                fortigate_response="blocked_on_firewall" if fg_blocked else None,
                fortigate_sync_error=fg_error,
            )
            session.add(cache_record)

        # Commit transaction
        await session.commit()

        # === STEP 5: Return verdict ===
        response_data = {
            "action": action,
            "source_ip": source_ip,
            "reputation_score": malicious_count,
            "cached": False,
            "expires_at": expires_at.isoformat(),
        }

        # Include full VirusTotal data only if call succeeded
        if not vt_call_failed:
            response_data["virustotal"] = vt_data
        else:
            response_data["virustotal_error"] = vt_error_message
            response_data["using_fallback"] = True
            response_data["warning"] = f"VirusTotal unavailable, using default fallback values: reputation_score=5, action=BLOCK"

        if fortigate_status:
            response_data["fortigate"] = fortigate_status

        return response_data
