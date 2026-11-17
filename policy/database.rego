package main

import rego.v1

# AZ-008  SQL server reachable from the internet
#
# Attack: a database with a public endpoint can be attacked directly with
# password guessing or a vulnerability, without first getting into the network.
deny contains result if {
	some [address, config] in resources("azurerm_mssql_server")
	object.get(config, "public_network_access_enabled", true) == true
	result := finding(
		"AZ-008", "HIGH", address,
		"the database server has a public endpoint.",
		"set public_network_access_enabled = false and use a private endpoint.",
	)
}
