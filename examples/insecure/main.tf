# !! INTENTIONALLY INSECURE - DO NOT DEPLOY !!
#
# Every resource in this file contains a mistake that is common in real
# projects. The pipeline checks that the guardrails catch all of them.
# The secure version of the same environment is in ../secure/main.tf.

resource "azurerm_resource_group" "this" {
  name     = "rg-demo"
  location = "westeurope"
}

# AZ-009: a password as the default value of a variable.
variable "sql_admin_password" {
  type    = string
  default = "Welcome2024!"
}

# AZ-001: public blob access is left on.  AZ-002: old TLS allowed.
resource "azurerm_storage_account" "data" {
  name                            = "stdemodata"
  resource_group_name             = azurerm_resource_group.this.name
  location                        = azurerm_resource_group.this.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
  min_tls_version                 = "TLS1_0"
}

# AZ-003: SSH and RDP reachable from the whole internet.
resource "azurerm_network_security_group" "vm" {
  name                = "nsg-demo-vm"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location

  security_rule {
    name                       = "allow-ssh"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "*"
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "22"
  }

  security_rule {
    name                       = "allow-rdp"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "0.0.0.0/0"
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "3389"
  }
}

# AZ-004: no purge protection.  AZ-005: no firewall.
resource "azurerm_key_vault" "main" {
  name                = "kv-demo"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"
}

# AZ-009: the secret value is typed into the code.
resource "azurerm_key_vault_secret" "api" {
  name         = "api-key"
  key_vault_id = azurerm_key_vault.main.id
  value        = "example-api-key-not-real"
}

# AZ-006: HTTP is not switched off.
resource "azurerm_linux_web_app" "site" {
  name                = "app-demo"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  service_plan_id     = "replace-with-plan-id"

  site_config {}
}

# AZ-007: password login on a VM.  AZ-009: the password itself is in the code.
resource "azurerm_linux_virtual_machine" "jump" {
  name                            = "vm-demo-jump"
  resource_group_name             = azurerm_resource_group.this.name
  location                        = azurerm_resource_group.this.location
  size                            = "Standard_B1s"
  admin_username                  = "azureuser"
  admin_password                  = "P@ssw0rd123!"
  disable_password_authentication = false
  network_interface_ids           = []

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
}

# AZ-008: database with a public endpoint.
resource "azurerm_mssql_server" "db" {
  name                         = "sql-demo"
  resource_group_name          = azurerm_resource_group.this.name
  location                     = azurerm_resource_group.this.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password
}
