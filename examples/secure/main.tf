# The same environment as ../insecure/main.tf, with every finding fixed.
# The guardrails must report nothing for this file.

resource "azurerm_resource_group" "this" {
  name     = "rg-demo"
  location = "westeurope"
}

# No default: the value is supplied at deploy time and hidden in the output.
variable "sql_admin_password" {
  type      = string
  sensitive = true
}

variable "api_key" {
  type      = string
  sensitive = true
}

variable "admin_ip_range" {
  description = "Office or VPN range that may reach the management port."
  type        = string
}

variable "admin_ssh_public_key" {
  type = string
}

resource "azurerm_storage_account" "data" {
  name                            = "stdemodata"
  resource_group_name             = azurerm_resource_group.this.name
  location                        = azurerm_resource_group.this.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = false
  min_tls_version                 = "TLS1_2"
}

resource "azurerm_network_security_group" "vm" {
  name                = "nsg-demo-vm"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location

  # SSH only from a known range. There is no RDP rule at all.
  security_rule {
    name                       = "allow-ssh-from-admin-range"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = var.admin_ip_range
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "22"
  }
}

resource "azurerm_key_vault" "main" {
  name                     = "kv-demo"
  resource_group_name      = azurerm_resource_group.this.name
  location                 = azurerm_resource_group.this.location
  tenant_id                = "00000000-0000-0000-0000-000000000000"
  sku_name                 = "standard"
  purge_protection_enabled = true

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

resource "azurerm_key_vault_secret" "api" {
  name         = "api-key"
  key_vault_id = azurerm_key_vault.main.id
  value        = var.api_key
}

resource "azurerm_linux_web_app" "site" {
  name                = "app-demo"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  service_plan_id     = "replace-with-plan-id"
  https_only          = true

  site_config {}
}

resource "azurerm_linux_virtual_machine" "jump" {
  name                  = "vm-demo-jump"
  resource_group_name   = azurerm_resource_group.this.name
  location              = azurerm_resource_group.this.location
  size                  = "Standard_B1s"
  admin_username        = "azureuser"
  network_interface_ids = []

  # Key-based login only (password login is off by default).
  admin_ssh_key {
    username   = "azureuser"
    public_key = var.admin_ssh_public_key
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
}

resource "azurerm_mssql_server" "db" {
  name                          = "sql-demo"
  resource_group_name           = azurerm_resource_group.this.name
  location                      = azurerm_resource_group.this.location
  version                       = "12.0"
  administrator_login           = "sqladmin"
  administrator_login_password  = var.sql_admin_password
  public_network_access_enabled = false
}
