package main

import rego.v1

# AZ-000  Security setting that cannot be checked from the code alone
#
# When a security-relevant setting is filled from a variable, its real value is
# only known at `terraform plan` time. This is a warning, not a failure: it
# tells the reviewer to check the value that will actually be used.

checked_settings := {
	["azurerm_storage_account", "allow_nested_items_to_be_public"],
	["azurerm_storage_account", "min_tls_version"],
	["azurerm_key_vault", "purge_protection_enabled"],
	["azurerm_key_vault", "public_network_access_enabled"],
	["azurerm_linux_web_app", "https_only"],
	["azurerm_windows_web_app", "https_only"],
	["azurerm_linux_function_app", "https_only"],
	["azurerm_windows_function_app", "https_only"],
	["azurerm_linux_virtual_machine", "disable_password_authentication"],
	["azurerm_mssql_server", "public_network_access_enabled"],
}

warn contains result if {
	some [type, setting] in checked_settings
	some [address, config] in resources(type)
	is_reference(config[setting])
	result := finding(
		"AZ-000", "INFO", address,
		sprintf("\"%s\" is set from %s, so its real value is unknown here.", [setting, config[setting]]),
		"check the value in the plan output, or set it directly.",
	)
}
