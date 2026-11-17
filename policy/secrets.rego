package main

import rego.v1

# AZ-009  Secret written directly in the code
#
# Attack: code is copied, shared and kept in Git history forever. Anyone who
# can read the repository - now or years later - has the password. Leaked
# credentials in code are one of the most common ways attackers get in.

secret_name := `(?i)(password|passwd|secret|token|api_key|access_key|connection_string)$`

is_hardcoded(value) if {
	is_string(value)
	value != ""
	not is_reference(value)
}

# A setting with a secret-like name and a literal value, anywhere in a resource.
deny contains result if {
	some type, named in input.resource
	some name, blocks in named
	some config in blocks
	walk(config, [path, value])
	count(path) > 0
	key := path[count(path) - 1]
	is_string(key)
	regex.match(secret_name, key)
	is_hardcoded(value)
	result := finding(
		"AZ-009", "CRITICAL", sprintf("%s.%s", [type, name]),
		sprintf("the value of \"%s\" is written directly in the code.", [key]),
		"pass it in through a sensitive variable or read it from Key Vault.",
	)
}

# A Key Vault secret whose value is typed into the file.
deny contains result if {
	some [address, config] in resources("azurerm_key_vault_secret")
	is_hardcoded(config.value)
	result := finding(
		"AZ-009", "CRITICAL", address,
		"the secret value is written directly in the code.",
		"pass it in through a sensitive variable.",
	)
}

# A variable with a secret-like name that ships with a real default value.
deny contains result if {
	some name, blocks in input.variable
	regex.match(secret_name, name)
	some block in blocks
	is_hardcoded(block.default)
	result := finding(
		"AZ-009", "CRITICAL", sprintf("var.%s", [name]),
		"this variable has a secret as its default value.",
		"remove the default and mark the variable sensitive = true.",
	)
}
