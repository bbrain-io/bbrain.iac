from __future__ import annotations

import asyncio
from ipaddress import IPv4Address
from typing import List, TYPE_CHECKING

from bbrain.iac.ovh.exceptions import HTTPBadRequest, HTTPConflict, HTTPNotFound
from bbrain.iac.ovh.models.ip import (
    FirewallIp,
    FirewallNetworkRule,
    FirewallRuleStateEnum,
    FirewallStateEnum,
    IpTask,
)
from bbrain.iac.ovh.api import wait_until

if TYPE_CHECKING:
    from bbrain.iac.ovh.client import Client


async def create_firewall(client: Client, ip: IPv4Address) -> None:
    """Create a firewall for an IP, then wait for it to be created

    Args:
        client (Client): An OVH client
        ip (IPv4Address): The IP to create the firewall for
    """
    await client.post(f"/ip/{ip}/firewall", json={"ipOnFirewall": ip})

    while await get_firewall_properties(client, ip) is None:
        await asyncio.sleep(2)


async def enable_firewall(client: Client, ip: IPv4Address) -> None:
    """Enables the firewall for an IP

    Args:
        client (Client): An OVH client
        ip (IPv4Address): The IP to enable the firewall for

    Raises:
        ValueError: When no firewall exists for the IP
    """
    properties = await get_firewall_properties(client, ip)
    if properties is None:
        raise ValueError

    while properties.state != FirewallStateEnum.ok:
        await asyncio.sleep(2)
        properties = await get_firewall_properties(client, ip)

    await client.put(f"/ip/{ip}/firewall/{ip}", json={"enabled": True})


async def get_firewall_properties(client: Client, ip: IPv4Address) -> FirewallIp | None:
    """Gets a firewall's properties

    Args:
        client (Client): An OVH client
        ip (IPv4Address): The firewall's IP

    Returns:
        FirewallIp | None: The firewall's properties
    """
    try:
        async with client.get(f"/ip/{ip}/firewall/{ip}") as res:
            json_data = await res.json()
    except HTTPNotFound:
        return None

    return FirewallIp(**json_data)


async def get_firewall_rule(
    client: Client, ip: IPv4Address, sequence: int
) -> FirewallNetworkRule | None:
    """Gets a firewall rule by its sequence number

    Args:
        client (Client): An OVH client
        ip (IPv4Address): The IP where to fetch the rule
        sequence (int): The sequence number

    Returns:
        FirewallNetworkRule: The resulting network rule
    """
    try:
        async with client.get(f"/ip/{ip}/firewall/{ip}/rule/{sequence}") as res:
            json_data = await res.json()
    except HTTPNotFound:
        return None

    return FirewallNetworkRule(**json_data)


async def get_firewall_rules_ids(client: Client, ip: IPv4Address) -> List[int]:
    """Gets the list of firewall rules sequence ids for an IP

    Args:
        client (Client): An OVH client
        ip (IPv4Address): The IP address to get the rules for

    Returns:
        List[int]: The list of rules sequence ids
    """
    try:
        async with client.get(f"/ip/{ip}/firewall/{ip}/rule") as res:
            json_data = await res.json()
    except HTTPNotFound:
        return []

    return json_data


async def post_firewall_rule(
    client: Client, ip: IPv4Address, rule: FirewallNetworkRule
) -> None:
    """Create a firewall rule

    Args:
        client (Client): An OVH client
        ip (IPv4Address): The IP address to create the rule for
        rule (FirewallNetworkRule): The rule

    Raises:
        HTTPConflict: When a rule with the same sequence already exists
    """
    try:
        async with client.post(
            f"/ip/{ip}/firewall/{ip}/rule", json=rule, raise_for_status=False
        ) as res:
            json_data = await res.json()
            res.raise_for_status()
    except HTTPBadRequest as err:
        if "exists" in json_data.get("message", ""):
            raise HTTPConflict(*err.args) from err
        raise


async def delete_firewall_rule(
    client: Client, ip: IPv4Address, seq: int, timeout: int = 180
):
    """Delete a firewall rule

    Args:
        client (Client): An OVH client
        ip (IPv4Address): The IP address to delete the rule for
        seq (int): The sequence id of the rule to delete
    """

    def rule_pending(rule: FirewallNetworkRule | None):
        return rule is not None and rule.state != FirewallRuleStateEnum.ok

    # Wait for rule to be in state Ok
    await wait_until(
        get_firewall_rule, (client, ip, seq), rule_pending, timeout=timeout
    )
    await client.delete(f"/ip/{ip}/firewall/{ip}/rule/{seq}")

    # Wait for rule to be deleted
    await wait_until(
        get_firewall_rule, (client, ip, seq), rule_pending, timeout=timeout
    )


async def post_ip_move(client: Client, ip: IPv4Address, target: str):
    """Move an IP to a different service

    Args:
        client (Client): An OVH client
        ip (IPv4Address): The IP address to move
        target (str): The target service
    """
    await client.post(f"/ip/{ip}/move", json={"to": target})


async def get_ip_tasks(client: Client, ip: IPv4Address) -> List[int]:
    """Get the list of tasks for an IP

    Args:
        client (Client): An OVH client
        ip (IPv4Address): The IP address

    Returns:
        List[str]: The list of tasks
    """
    try:
        async with client.get(f"/ip/{ip}/task") as res:
            json_data = await res.json()
    except HTTPNotFound:
        return []

    if not isinstance(json_data, list):
        raise ValueError("Unexpected response. get_ip_tasks should return a list.")

    json_data.sort()
    return json_data


async def get_ip_task(client: Client, ip: IPv4Address, task_id: str) -> IpTask | None:
    """Get a task for an IP

    Args:
        client (Client): An OVH client
        ip (IPv4Address): The IP address
        task_id (str): The task id

    Returns:
        Task: The task
    """
    try:
        async with client.get(f"/ip/{ip}/task/{task_id}", raise_for_status=True) as res:
            return IpTask(**await res.json())
    except HTTPNotFound:
        return None
