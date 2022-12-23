from bbrain.iac.ovh.manifests.ip import (
    FirewallManifest,
    FirewallRuleManifest,
    FirewallSetManifest,
)

from bbrain.iac.ovh.exceptions import UnknownManifest


def manifest_factory(manifest: dict):
    manifest_map = {
        "firewall": FirewallManifest,
        "firewallrule": FirewallRuleManifest,
        "firewallset": FirewallSetManifest,
    }
    manifest_kind = manifest.get("kind", "").lower()

    try:
        return manifest_map[manifest_kind]
    except KeyError:
        raise UnknownManifest
