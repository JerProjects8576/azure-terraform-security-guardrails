package main

import rego.v1

# AZ-001  Storage account allows public blob access
#
# Attack: anyone on the internet who finds or guesses the URL can download the
# data, no login needed. Public storage is one of the most common causes of
# cloud data leaks.
#
# The Azure provider allows public access unless it is switched off, so leaving
# the setting out is also a failure.
deny contains result if {
	some [address, config] in resources("azurerm_storage_account")
	object.get(config, "allow_nested_items_to_be_public", true) == true
	result := finding(
		"AZ-001", "HIGH", address,
		"blobs in this storage account can be made publicly readable.",
		"set allow_nested_items_to_be_public = false.",
	)
}

# AZ-002  Storage account accepts outdated TLS versions
#
# Attack: TLS 1.0 and 1.1 have known weaknesses. An attacker who can intercept
# the connection may be able to read or change data in transit.
deny contains result if {
	some [address, config] in resources("azurerm_storage_account")
	config.min_tls_version in {"TLS1_0", "TLS1_1"}
	result := finding(
		"AZ-002", "MEDIUM", address,
		sprintf("accepts connections using %s.", [config.min_tls_version]),
		"set min_tls_version = \"TLS1_2\".",
	)
}
