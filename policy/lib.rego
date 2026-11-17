package main

import rego.v1

# Shared helpers used by every rule.
#
# Conftest turns a Terraform file into data shaped like this:
#
#   input.resource.<type>.<name> = [ { ...the resource's settings... } ]
#
# so `resources("azurerm_key_vault")` gives every Key Vault in the file as a
# pair: its address (for example "azurerm_key_vault.main") and its settings.

resources(type) := {[address, config] |
	some name, blocks in input.resource[type]
	some config in blocks
	address := sprintf("%s.%s", [type, name])
}

# One consistent shape for every finding, so the output can be read by people
# and filtered by tools.
finding(id, severity, address, problem, fix) := {
	"msg": sprintf("%s [%s] %s: %s Fix: %s", [id, severity, address, problem, fix]),
	"rule": id,
	"severity": severity,
	"resource": address,
}

# True when a value comes from a variable or another resource, for example
# "${var.allow_public}". Such a value is unknown until `terraform plan`.
is_reference(value) if {
	is_string(value)
	contains(value, "${")
}
