package main

import rego.v1

# Unit tests for the rules. Each rule is tested twice: once with an insecure
# resource (the rule must fire) and once with a secure one (it must stay quiet).
#
#   conftest verify --policy policy

fired(results) := {result.rule | some result in results}

# ---- AZ-001: public blob access --------------------------------------------

test_az001_fires_when_public_access_is_on if {
	"AZ-001" in fired(deny) with input as {"resource": {"azurerm_storage_account": {"a": [{"allow_nested_items_to_be_public": true}]}}}
}

test_az001_fires_when_setting_is_missing if {
	"AZ-001" in fired(deny) with input as {"resource": {"azurerm_storage_account": {"a": [{"name": "st"}]}}}
}

test_az001_quiet_when_public_access_is_off if {
	not "AZ-001" in fired(deny) with input as {"resource": {"azurerm_storage_account": {"a": [{"allow_nested_items_to_be_public": false}]}}}
}

# ---- AZ-002: outdated TLS ---------------------------------------------------

test_az002_fires_on_tls_1_0 if {
	"AZ-002" in fired(deny) with input as {"resource": {"azurerm_storage_account": {"a": [{"min_tls_version": "TLS1_0"}]}}}
}

test_az002_quiet_on_tls_1_2_and_on_default if {
	not "AZ-002" in fired(deny) with input as {"resource": {"azurerm_storage_account": {
		"a": [{"min_tls_version": "TLS1_2"}],
		"b": [{"name": "default-is-1.2"}],
	}}}
}

# ---- AZ-003: management ports open to the internet --------------------------

nsg(rule) := {"resource": {"azurerm_network_security_group": {"n": [{"security_rule": [rule]}]}}}

open_rule := {
	"name": "r",
	"direction": "Inbound",
	"access": "Allow",
	"source_address_prefix": "*",
	"destination_port_range": "22",
}

test_az003_fires_on_ssh_from_anywhere if {
	"AZ-003" in fired(deny) with input as nsg(open_rule)
}

test_az003_fires_on_rdp_inside_a_port_range if {
	rule := object.union(open_rule, {"destination_port_range": "3000-4000", "source_address_prefix": "0.0.0.0/0"})
	"AZ-003" in fired(deny) with input as nsg(rule)
}

test_az003_fires_on_all_ports_from_internet_tag if {
	rule := object.union(open_rule, {"destination_port_range": "*", "source_address_prefix": "Internet"})
	count({result | some result in deny; result.rule == "AZ-003"}) == 2 with input as nsg(rule)
}

test_az003_fires_on_port_list_and_source_list if {
	rule := object.union(
		object.remove(open_rule, ["source_address_prefix", "destination_port_range"]),
		{"source_address_prefixes": ["10.0.0.0/8", "0.0.0.0/0"], "destination_port_ranges": ["443", "3389"]},
	)
	"AZ-003" in fired(deny) with input as nsg(rule)
}

test_az003_fires_on_standalone_rule_resource if {
	"AZ-003" in fired(deny) with input as {"resource": {"azurerm_network_security_rule": {"r": [open_rule]}}}
}

test_az003_quiet_when_source_is_restricted if {
	rule := object.union(open_rule, {"source_address_prefix": "203.0.113.10/32"})
	not "AZ-003" in fired(deny) with input as nsg(rule)
}

test_az003_quiet_for_https_from_anywhere if {
	rule := object.union(open_rule, {"destination_port_range": "443"})
	not "AZ-003" in fired(deny) with input as nsg(rule)
}

test_az003_quiet_for_deny_and_outbound_rules if {
	not "AZ-003" in fired(deny) with input as nsg(object.union(open_rule, {"access": "Deny"}))
	not "AZ-003" in fired(deny) with input as nsg(object.union(open_rule, {"direction": "Outbound"}))
}

# ---- AZ-004 / AZ-005: Key Vault ---------------------------------------------

test_az004_fires_without_purge_protection if {
	"AZ-004" in fired(deny) with input as {"resource": {"azurerm_key_vault": {"k": [{"name": "kv"}]}}}
}

test_az004_quiet_with_purge_protection if {
	not "AZ-004" in fired(deny) with input as {"resource": {"azurerm_key_vault": {"k": [{"purge_protection_enabled": true}]}}}
}

test_az005_fires_without_firewall if {
	"AZ-005" in fired(deny) with input as {"resource": {"azurerm_key_vault": {"k": [{"name": "kv"}]}}}
}

test_az005_fires_when_firewall_allows_by_default if {
	"AZ-005" in fired(deny) with input as {"resource": {"azurerm_key_vault": {"k": [{"network_acls": [{"default_action": "Allow"}]}]}}}
}

test_az005_quiet_when_firewall_denies_by_default if {
	not "AZ-005" in fired(deny) with input as {"resource": {"azurerm_key_vault": {"k": [{"network_acls": [{"default_action": "Deny"}]}]}}}
}

test_az005_quiet_when_public_access_is_off if {
	not "AZ-005" in fired(deny) with input as {"resource": {"azurerm_key_vault": {"k": [{"public_network_access_enabled": false}]}}}
}

# ---- AZ-006: HTTPS only -----------------------------------------------------

test_az006_fires_for_every_app_type_without_https_only if {
	count({result.resource | some result in deny; result.rule == "AZ-006"}) == 4 with input as {"resource": {
		"azurerm_linux_web_app": {"a": [{"name": "a"}]},
		"azurerm_windows_web_app": {"b": [{"https_only": false}]},
		"azurerm_linux_function_app": {"c": [{"name": "c"}]},
		"azurerm_windows_function_app": {"d": [{"name": "d"}]},
	}}
}

test_az006_quiet_with_https_only if {
	not "AZ-006" in fired(deny) with input as {"resource": {"azurerm_linux_web_app": {"a": [{"https_only": true}]}}}
}

# ---- AZ-007: VM password login ----------------------------------------------

test_az007_fires_when_password_login_is_enabled if {
	"AZ-007" in fired(deny) with input as {"resource": {"azurerm_linux_virtual_machine": {"v": [{"disable_password_authentication": false}]}}}
}

test_az007_quiet_on_default if {
	not "AZ-007" in fired(deny) with input as {"resource": {"azurerm_linux_virtual_machine": {"v": [{"name": "vm"}]}}}
}

# ---- AZ-008: public SQL server ----------------------------------------------

test_az008_fires_on_default_public_endpoint if {
	"AZ-008" in fired(deny) with input as {"resource": {"azurerm_mssql_server": {"s": [{"name": "sql"}]}}}
}

test_az008_quiet_when_public_access_is_off if {
	not "AZ-008" in fired(deny) with input as {"resource": {"azurerm_mssql_server": {"s": [{"public_network_access_enabled": false}]}}}
}

# ---- AZ-009: hardcoded secrets ----------------------------------------------

test_az009_fires_on_literal_password if {
	"AZ-009" in fired(deny) with input as {"resource": {"azurerm_mssql_server": {"s": [{"administrator_login_password": "Welcome123!"}]}}}
}

test_az009_fires_on_secret_in_nested_block if {
	"AZ-009" in fired(deny) with input as {"resource": {"azurerm_linux_web_app": {"a": [{"site_config": [{"application_stack": [{"docker_registry_password": "abc"}]}]}]}}}
}

test_az009_fires_on_literal_key_vault_secret if {
	"AZ-009" in fired(deny) with input as {"resource": {"azurerm_key_vault_secret": {"s": [{"name": "db", "value": "hunter2"}]}}}
}

test_az009_fires_on_variable_with_secret_default if {
	"AZ-009" in fired(deny) with input as {"variable": {"db_password": [{"default": "hunter2"}]}}
}

test_az009_quiet_when_secret_comes_from_a_variable if {
	not "AZ-009" in fired(deny) with input as {
		"resource": {"azurerm_mssql_server": {"s": [{"administrator_login_password": "${var.db_password}"}]}},
		"variable": {"db_password": [{"sensitive": true}]},
	}
}

test_az009_quiet_for_names_that_only_mention_a_secret if {
	not "AZ-009" in fired(deny) with input as {"resource": {"azurerm_linux_virtual_machine": {"v": [{
		"disable_password_authentication": true,
		"secret_name": "app-secret",
	}]}}}
}

# ---- AZ-000: values that cannot be verified ---------------------------------

test_az000_warns_when_setting_comes_from_a_variable if {
	"AZ-000" in fired(warn) with input as {"resource": {"azurerm_linux_web_app": {"a": [{"https_only": "${var.https_only}"}]}}}
}

test_az000_does_not_also_fail_the_same_setting if {
	not "AZ-006" in fired(deny) with input as {"resource": {"azurerm_linux_web_app": {"a": [{"https_only": "${var.https_only}"}]}}}
}

test_az000_quiet_for_literal_values if {
	count(warn) == 0 with input as {"resource": {"azurerm_linux_web_app": {"a": [{"https_only": true}]}}}
}

# ---- No resources at all ----------------------------------------------------

test_nothing_fires_on_an_empty_file if {
	count(deny) == 0 with input as {}
	count(warn) == 0 with input as {}
}
