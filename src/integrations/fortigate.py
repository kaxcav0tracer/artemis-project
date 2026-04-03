"""FortiGate Active Response Integration"""

from typing import Any
import httpx


class FortiGateAPI:
    """FortiGate REST API client for blocking IPs on Firewall"""

    def __init__(self, fg_url: str, fg_api_token: str) -> None:
        """Initialize FortiGate API client

        Args:
            fg_url: FortiGate API base URL (e.g., https://192.168.1.99)
            fg_api_token: FortiGate API token for authentication
        """
        self.fg_url = fg_url.rstrip("/")
        self.fg_api_token = fg_api_token
        self.headers = {
            "Authorization": f"Bearer {fg_api_token}",
            "Content-Type": "application/json",
        }

    async def block_ip(self, ip_address: str, **kwargs: Any) -> dict[str, Any]:
        """Block an IP address by creating address object and adding to blocklist group

        Args:
            ip_address: IP address to block
            **kwargs: Additional parameters (name, comment, etc)

        Returns:
            Response dict with keys:
                - success: Whether the operation succeeded
                - message: Human-readable status message
                - error: Error message if failed
        """
        try:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client: # nosec
                # Step 1: Create address object
                address_name = f"artemis_block_{ip_address.replace('.', '_')}"
                address_data = {
                    "name": address_name,
                    "subnet": f"{ip_address}/32",
                    "comment": "Blocked by Artemis SOAR - High reputation threat",
                }

                create_url = f"{self.fg_url}/api/v2/cmdb/firewall/address"

                create_response = await client.post(
                    create_url,
                    json=address_data,
                    headers=self.headers,
                )

                if create_response.status_code not in [200, 201]:
                    # IP might already exist, try to get it
                    if create_response.status_code == 424:  # Object already exists
                        return {
                            "success": True,
                            "message": f"IP {ip_address} already exists in FortiGate",
                            "error": None,
                        }
                    return {
                        "success": False,
                        "message": f"Failed to create address object for {ip_address}",
                        "error": create_response.text,
                    }

                # Step 2: Add address to Artemis_Blocklist group
                group_url = f"{self.fg_url}/api/v2/cmdb/firewall/addrgrp/Artemis_Blocklist"
                group_data = {
                    "member": [{"name": address_name}],
                }

                group_response = await client.put(
                    group_url,
                    json=group_data,
                    headers=self.headers,
                )

                if group_response.status_code not in [200, 201]:
                    # If group doesn't exist, create it first
                    if group_response.status_code == 404:
                        create_group_url = f"{self.fg_url}/api/v2/cmdb/firewall/addrgrp"
                        group_create_data = {
                            "name": "Artemis_Blocklist",
                            "member": [{"name": address_name}],
                            "comment": "Dynamic blocklist managed by Artemis SOAR",
                        }

                        group_create_response = await client.post(
                            create_group_url,
                            json=group_create_data,
                            headers=self.headers,
                        )

                        if group_create_response.status_code not in [200, 201]:
                            return {
                                "success": False,
                                "message": f"Failed to create Artemis_Blocklist group",
                                "error": group_create_response.text,
                            }
                    else:
                        return {
                            "success": False,
                            "message": f"Failed to add {ip_address} to Artemis_Blocklist",
                            "error": group_response.text,
                        }

                return {
                    "success": True,
                    "message": f"IP {ip_address} blocked successfully on FortiGate",
                    "error": None,
                }

        except httpx.HTTPError as e:
            return {
                "success": False,
                "message": f"HTTP error while connecting to FortiGate",
                "error": str(e),
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Unexpected error during FortiGate blocking",
                "error": str(e),
            }
