package main

import rego.v1

# AZ-006  Web app accepts unencrypted HTTP
#
# Attack: on an untrusted network (public Wi-Fi, a compromised router) an
# attacker can read or change everything sent over plain HTTP, including
# session cookies and passwords.

web_app_types := {
	"azurerm_linux_web_app",
	"azurerm_windows_web_app",
	"azurerm_linux_function_app",
	"azurerm_windows_function_app",
}

deny contains result if {
	some type in web_app_types
	some [address, config] in resources(type)
	object.get(config, "https_only", false) == false
	result := finding(
		"AZ-006", "HIGH", address,
		"the app also answers over unencrypted HTTP.",
		"set https_only = true.",
	)
}

# AZ-007  Linux VM allows password logins
#
# Attack: passwords can be guessed or reused from other breaches. SSH keys
# cannot be brute-forced in practice.
deny contains result if {
	some [address, config] in resources("azurerm_linux_virtual_machine")
	config.disable_password_authentication == false
	result := finding(
		"AZ-007", "HIGH", address,
		"users can log in with a password instead of an SSH key.",
		"remove disable_password_authentication = false and use admin_ssh_key.",
	)
}
