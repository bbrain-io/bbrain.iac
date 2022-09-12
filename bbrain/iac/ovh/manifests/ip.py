import logging
import asyncio
from typing import List
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network

from pythonjsonlogger.jsonlogger import JsonFormatter

from bbrain.iac import BaseDataclass, json
from bbrain.iac.ovh import BaseManifest
from bbrain.iac.ovh.client import Client
from bbrain.iac.ovh.api.ip import (
    create_firewall,
    enable_firewall,
    delete_firewall_rule,
    get_firewall_properties,
    get_firewall_rule,
    get_firewall_rules_ids,
    post_firewall_rule,
)
from bbrain.iac.ovh.models.ip import (
    FirewallActionEnum,
    FirewallNetworkRule,
    FirewallOptionTCP,
    FirewallProtocolEnum,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = JsonFormatter(
    "%(levelname)s %(lineno)s %(filename)s %(funcName)s %(module)s %(msg)s",
    json_encoder=json.CustomEncoder,
    timestamp=True,
)
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)


@dataclass
class FirewallRuleManifest(BaseManifest, BaseDataclass):
    sequence: int
    action: FirewallActionEnum
    protocol: FirewallProtocolEnum
    destinationPort: int | None = None
    source: IPv4Network | None = None
    sourcePort: int | None = None
    tcpOption: FirewallOptionTCP | None = None

    def __post_init__(self):
        super().__post_init__()

        if self.protocol is FirewallProtocolEnum.tcp and not self.tcpOption:
            self.tcpOption = FirewallOptionTCP()

    async def apply(self, client: Client, target: IPv4Address = IPv4Address(0)):
        resource = f"/ip/{target}/firewall/{target}/rule/{self.sequence}"

        logger.debug(self.__json__())
        ids = await get_firewall_rules_ids(client, target)
        rule = await get_firewall_rule(client, target, self.sequence)
        if self == rule:
            logger.info(f"Skipping existing rule.", extra={"resource": resource})
            return

        if self.sequence in ids:
            await delete_firewall_rule(client, target, self.sequence)

        await post_firewall_rule(client, target, self)

    def rulestr(self, target: IPv4Address):
        a = self.action.name.upper().ljust(8, " ")
        p = self.protocol.name.upper().ljust(4, " ")
        s = str(self.source or "any").rjust(18, " ")
        sp = str(self.sourcePort or "*").ljust(5, " ")
        d = str(target).rjust(18, " ")
        dp = str(self.destinationPort or "*").ljust(5, " ")
        return f"{a} {p} {s}:{sp} -> {d}:{dp}"

    def __eq__(self, __o: object) -> bool:
        if isinstance(__o, FirewallNetworkRule):
            return self.__json__() == __o.__manifest__()
        return NotImplemented


@dataclass
class FirewallManifest(BaseManifest, BaseDataclass):
    ip: IPv4Address
    enabled: bool
    rules: List[FirewallRuleManifest]

    async def apply(self, client: Client):
        logger.info(f"Applying Firewall manifest for {self.ip}")
        self.properties = await get_firewall_properties(client, self.ip)

        if not self.properties:
            logger.info(f"Creating firewall for {self.ip}")
            await create_firewall(client, self.ip)
            self.properties = await get_firewall_properties(client, self.ip)

        if self.properties is None:
            raise Exception

        if not self.properties.enabled:
            logger.info(f"Enabling firewall for {self.ip}")
            await enable_firewall(client, self.ip)

        rules_coroutines = [r.apply(client, self.ip) for r in self.rules]
        await asyncio.gather(*rules_coroutines)


@dataclass
class FirewallSetManifest(BaseManifest, BaseDataclass):
    configs: List[FirewallManifest]
    rules: dict
    kind: str = "FirewallSet"

    async def apply(self, client: Client):
        logger.info("Applying FirewallSet manifest")
        coroutines = [fw.apply(client) for fw in self.configs]
        await asyncio.gather(*coroutines)
