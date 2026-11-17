# Rule catalogue

Each rule is described from the attacker's side first: what the mistake makes
possible. The MITRE ATT&CK technique is the closest match for that attack.

## AZ-001 - Storage account allows public blob access

- **Severity:** High
- **Checks:** `azurerm_storage_account` must set `allow_nested_items_to_be_public = false`.
  Leaving the setting out also fails, because the provider's default is `true`.
- **Attack:** containers can be made anonymous. Anyone who finds or guesses the
  URL downloads the contents without logging in. Attackers scan for these
  automatically.
- **ATT&CK:** T1530 Data from Cloud Storage
- **Fix:** `allow_nested_items_to_be_public = false`

## AZ-002 - Storage account accepts outdated TLS

- **Severity:** Medium
- **Checks:** `min_tls_version` must not be `TLS1_0` or `TLS1_1`.
- **Attack:** old TLS versions have known weaknesses that help an attacker who
  can intercept traffic to read or alter it.
- **ATT&CK:** T1557 Adversary-in-the-Middle
- **Fix:** `min_tls_version = "TLS1_2"`

## AZ-003 - Management port open to the whole internet

- **Severity:** Critical
- **Checks:** no inbound *allow* rule from `*`, `0.0.0.0/0`, `::/0` or
  `Internet` that covers port 22 (SSH) or 3389 (RDP). Covers rules written
  inside the NSG and as separate resources, single ports, port lists, ranges
  such as `3000-4000`, and `*`.
- **Attack:** exposed SSH and RDP are found by scanners within minutes and hit
  with password guessing and exploits. A working login gives a foothold inside
  the network.
- **ATT&CK:** T1133 External Remote Services, T1110 Brute Force
- **Fix:** restrict the source to a known range, or use Azure Bastion or a VPN.

## AZ-004 - Key Vault without purge protection

- **Severity:** Medium
- **Checks:** `azurerm_key_vault` must set `purge_protection_enabled = true`.
- **Attack:** someone with access deletes the vault and purges it. All keys and
  secrets are gone for good, and encrypted data that depends on them is lost.
- **ATT&CK:** T1485 Data Destruction
- **Fix:** `purge_protection_enabled = true`

## AZ-005 - Key Vault reachable from any network

- **Severity:** High
- **Checks:** the vault must have a `network_acls` block that does not allow by
  default, or have `public_network_access_enabled = false`.
- **Attack:** a stolen token or leaked credential can be used from anywhere in
  the world. With a firewall the attacker also needs to be on an allowed network.
- **ATT&CK:** T1078 Valid Accounts
- **Fix:** `network_acls { default_action = "Deny" }`, ideally with a private endpoint.

## AZ-006 - Web app accepts unencrypted HTTP

- **Severity:** High
- **Checks:** Linux/Windows web apps and function apps must set `https_only = true`.
- **Attack:** on an untrusted network, plain HTTP traffic can be read and
  changed, including session cookies and passwords.
- **ATT&CK:** T1040 Network Sniffing
- **Fix:** `https_only = true`

## AZ-007 - Linux VM allows password logins

- **Severity:** High
- **Checks:** `azurerm_linux_virtual_machine` must not set
  `disable_password_authentication = false`.
- **Attack:** passwords are guessed or reused from other breaches. SSH keys are
  not practical to brute-force.
- **ATT&CK:** T1110 Brute Force
- **Fix:** remove the setting and use an `admin_ssh_key` block.

## AZ-008 - SQL server reachable from the internet

- **Severity:** High
- **Checks:** `azurerm_mssql_server` must set `public_network_access_enabled = false`.
- **Attack:** a public database endpoint can be attacked directly, without
  first getting into the network.
- **ATT&CK:** T1190 Exploit Public-Facing Application
- **Fix:** `public_network_access_enabled = false` plus a private endpoint.

## AZ-009 - Secret written directly in the code

- **Severity:** Critical
- **Checks:** three patterns:
  1. any resource setting whose name ends in `password`, `secret`, `token`,
     `api_key`, `access_key` or `connection_string` and has a literal value;
  2. an `azurerm_key_vault_secret` with a literal `value`;
  3. a variable with such a name and a non-empty `default`.
- **Attack:** code is copied, shared and kept in Git history. Anyone who can
  read the repository - now or later - has the credential.
- **ATT&CK:** T1552.001 Unsecured Credentials: Credentials In Files
- **Fix:** use a variable marked `sensitive = true` without a default, or read
  the value from Key Vault.

## AZ-000 - Setting cannot be verified from the code (warning)

- **Severity:** Info
- **Checks:** a setting used by one of the rules above is filled from a
  variable or expression, for example `https_only = var.https_only`.
- **Why a warning:** the real value is only known at `terraform plan`. Failing
  would block correct code; passing silently would hide a possible problem. The
  reviewer is told to check.
