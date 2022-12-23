from bbrain.iac.ovh.client import Client


async def put_dedicated_server(client: Client, server: str, bootId: int, **kwargs):
    """Updates dedicated server info"""

    payload = {
        "bootId": bootId,
        "monitoring": kwargs.get("monitoring", False),
        "noIntervention": kwargs.get("noIntervention", False),
        "state": kwargs.get("state", "ok"),
    }
    async with client.put(f"/dedicated/server/{server}", json=payload) as res:
        json_data = await res.json()

    return json_data


async def post_dedicated_server_reboot(client: Client, server: str):
    """Reboots a server"""
    await client.post(f"/dedicated/server/{server}/reboot")


async def post_dedicated_server_install(
    client: Client,
    server: str,
    template: str,
    hostname: str = None,
    sshKeyName: str = None,
    language: str = "en",
):
    """Installs a server with specified template"""
    if not hostname:
        hostname = server

    payload = {
        "templateName": template,
        "details": {
            "customHostname": hostname,
            "sshKeyName": sshKeyName,
            "language": language,
        },
    }
    async with client.post(
        f"/dedicated/server/{server}/install/start",
        json=payload,
        raise_for_status=False,
    ) as res:
        json_data = await res.json()

    return json_data
