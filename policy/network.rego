package main

import rego.v1

# AZ-003  Management port open to the whole internet
#
# Attack: SSH (22) and RDP (3389) exposed to the internet are found by
# automated scanners within minutes and then hit with password guessing and
# known exploits. This is a classic first step into a network.

management_ports := {22: "SSH", 3389: "RDP"}

internet_sources := {"*", "0.0.0.0/0", "::/0", "internet", "any"}

# Rules can be written inside the NSG or as a separate resource. Collect both.
nsg_rules contains [address, rule] if {
	some [address, config] in resources("azurerm_network_security_group")
	some rule in object.get(config, "security_rule", [])
}

nsg_rules contains [address, rule] if {
	some [address, rule] in resources("azurerm_network_security_rule")
}

sources(rule) := {lower(source) |
	some source in array.concat(
		[object.get(rule, "source_address_prefix", "")],
		object.get(rule, "source_address_prefixes", []),
	)
}

port_specs(rule) := {spec |
	some spec in array.concat(
		[object.get(rule, "destination_port_range", "")],
		object.get(rule, "destination_port_ranges", []),
	)
}

# A port specification can be "*", a single port ("22") or a range ("20-25").
covers(spec, _) if spec == "*"

covers(spec, port) if {
	regex.match(`^\d+$`, spec)
	to_number(spec) == port
}

covers(spec, port) if {
	regex.match(`^\d+-\d+$`, spec)
	bounds := split(spec, "-")
	to_number(bounds[0]) <= port
	port <= to_number(bounds[1])
}

deny contains result if {
	some [address, rule] in nsg_rules
	lower(rule.direction) == "inbound"
	lower(rule.access) == "allow"
	some source in sources(rule)
	source in internet_sources
	some port, service in management_ports
	some spec in port_specs(rule)
	covers(spec, port)
	result := finding(
		"AZ-003", "CRITICAL", address,
		sprintf("rule \"%s\" opens %s (port %d) to the whole internet.", [object.get(rule, "name", "unnamed"), service, port]),
		"limit the source to a known IP range, or use Azure Bastion or a VPN.",
	)
}
