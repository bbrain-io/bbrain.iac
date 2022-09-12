from bbrain.iac.ovh import BaseManifest
from bbrain.iac.ovh.manifests.ip import (
    FirewallManifest,
    FirewallRuleManifest,
    FirewallSetManifest,
)


class UnknownManifest(Exception):
    """Exception raised when a manifest is unknown"""


manifest_map = {
    "firewall": FirewallManifest,
    "firewallrule": FirewallRuleManifest,
    "firewallset": FirewallSetManifest,
}


def manifest_factory(manifest: dict) -> BaseManifest:
    manifest_kind = manifest.get("kind", "").lower()

    try:
        return manifest_map[manifest_kind]
    except KeyError:
        raise UnknownManifest
