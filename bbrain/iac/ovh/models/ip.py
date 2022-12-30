import re
from enum import auto
from typing import List
from datetime import datetime
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network

from bbrain.iac import AutoEnum, BaseDataclass, r


def ipv4network_parser(ip: str) -> IPv4Network | None:
    if ip == "any":
        return None
    return IPv4Network(ip)


def tcpoption_resolver(data):
    if isinstance(data, str):
        return FirewallTCPOptionEnum(data)
    elif isinstance(data, dict):
        return FirewallOptionTCP(**data)
    elif isinstance(data, FirewallOptionTCP):
        return data.__json__()
    elif isinstance(data, FirewallTCPOptionEnum):
        return str(data)

    raise ValueError


def port_parser(port):
    if isinstance(port, str):
        m: List[str] = re.findall(r"[0-9]+", port)
        if len(m) == 1:
            port = int(m[0])

    if isinstance(port, int) and 0 < port < 65535:
        return port

    raise ValueError(port)


class FirewallTCPOptionEnum(AutoEnum):
    established = auto()
    syn = auto()


class FirewallRuleStateEnum(AutoEnum):
    ok = auto()
    creationPending = auto()
    removalPending = auto()


class FirewallStateEnum(AutoEnum):
    disableFirewallPending = auto()
    enableFirewallPending = auto()
    ok = auto()


class FirewallActionEnum(AutoEnum):
    deny = auto()
    permit = auto()


class FirewallProtocolEnum(AutoEnum):
    ah = auto()
    esp = auto()
    gre = auto()
    icmp = auto()
    ipv4 = auto()
    tcp = auto()
    udp = auto()


class TaskStatusEnum(AutoEnum):
    cancelled = auto()
    customerError = auto()
    doing = auto()
    done = auto()
    init = auto()
    ovhError = auto()
    todo = auto()


class TaskFunctionEnum(AutoEnum):
    changeRipeOrg = auto()
    arinBlockReassign = auto()
    checkAndReleaseIp = auto()
    genericMoveFloatingIp = auto()


class NetworkPort:
    def __init__(self, port: str | int) -> None:
        pass


@dataclass
class FirewallOptionTCP(BaseDataclass):
    option: FirewallTCPOptionEnum | None = None
    fragments: bool = False


@dataclass
class FirewallIp(BaseDataclass):
    ipOnFirewall: IPv4Address = r(str)
    state: FirewallStateEnum = r(str)
    enabled: bool = r()

    def __json__(self):
        return {
            "enabled": self.enabled,
            "ipOnFirewall": str(self.ipOnFirewall),
            "state": self.state.name,
        }


@dataclass
class FirewallNetworkRule(BaseDataclass):
    sequence: int
    action: FirewallActionEnum
    protocol: FirewallProtocolEnum

    state: FirewallRuleStateEnum | None = None
    source: IPv4Network | None = r(parser=ipv4network_parser, default=None)
    sourcePort: int = r(parser=port_parser, default=None)
    destination: IPv4Network = r(parser=ipv4network_parser, default=None)
    destinationPort: int = r(parser=port_parser, default=None)
    tcpOption: FirewallTCPOptionEnum | None = None
    fragments: bool | None = None

    rule: str | None = None
    creationDate: datetime | None = r(parser=datetime.fromisoformat, default=None)

    def __manifest__(self):
        data = self.__json__()
        option = data.pop("tcpOption", None)
        fragments = data.pop("fragments", False)

        if self.protocol is FirewallProtocolEnum.tcp:
            data["tcpOption"] = FirewallOptionTCP(option, fragments)

        for k in ["creationDate", "destination", "state", "rule"]:
            data.pop(k, None)

        return data


@dataclass
class IpTask(BaseDataclass):
    taskId: int
    status: TaskStatusEnum
    function: TaskFunctionEnum
    comment: str | None = None
    destination: IPv4Address | None = None
    doneDate: datetime | None = r(parser=datetime.fromisoformat, default=None)
    startDate: datetime | None = r(parser=datetime.fromisoformat, default=None)
    lastUpdate: datetime | None = r(parser=datetime.fromisoformat, default=None)
