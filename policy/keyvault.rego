package main

import rego.v1

# AZ-004  Key Vault without purge protection
#
# Attack: an attacker (or an angry insider) with access deletes the vault and
# then purges it. Every key and secret is gone for good, and everything that
# depends on them stops working. Purge protection makes deletion recoverable.
deny contains result if {
	some [address, config] in resources("azurerm_key_vault")
	object.get(config, "purge_protection_enabled", false) == false
	result := finding(
		"AZ-004", "MEDIUM", address,
		"deleted secrets and keys can be permanently destroyed.",
		"set purge_protection_enabled = true.",
	)
}

# AZ-005  Key Vault reachable from any network
#
# Attack: with a stolen token or leaked credential, an attacker can read the
# secrets from anywhere in the world. A firewall that denies by default means
# they also need to be on an allowed network.

kv_firewall_denies(config) if {
	some acl in object.get(config, "network_acls", [])
	acl.default_action != "Allow"
}

kv_public_access_off(config) if config.public_network_access_enabled == false

deny contains result if {
	some [address, config] in resources("azurerm_key_vault")
	not kv_firewall_denies(config)
	not kv_public_access_off(config)
	result := finding(
		"AZ-005", "HIGH", address,
		"the vault accepts connections from any network.",
		"add a network_acls block with default_action = \"Deny\".",
	)
}
