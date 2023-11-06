resource "azurerm_resource_group" "demo" {
  name     = "rg-demo-sftp"
  location = "UKSouth"

  tags = {
    environment = "test"
  }
}

resource "random_string" "random" {
  length  = 5
  special = false
  numeric = false
  upper   = false
}

resource "random_string" "spe_random" {
  length  = 10
  special = true
  numeric = true
  upper   = true
}

resource "azurerm_network_security_group" "demo" {
  name                = format("%s-%s", "nsg", replace(azurerm_resource_group.demo.name, "rg-", ""))
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name

  tags = {
    environment = "test"
  }
}

resource "azurerm_network_security_rule" "demo" {
  for_each                    = local.network_security_rule
  name                        = each.key
  priority                    = each.value.priority
  direction                   = each.value.direction
  access                      = each.value.access
  protocol                    = each.value.protocol
  source_port_range           = each.value.source_port_range
  destination_port_ranges     = try(each.value.destination_port_ranges, null)
  destination_port_range      = try(each.value.destination_port_range, null)
  source_address_prefix       = each.value.source_address_prefix
  destination_address_prefix  = each.value.destination_address_prefix
  resource_group_name         = azurerm_resource_group.demo.name
  network_security_group_name = azurerm_network_security_group.demo.name
}


resource "azurerm_virtual_network" "demo" {
  name                = format("%s-%s", "vnet", replace(azurerm_resource_group.demo.name, "rg-", ""))
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name
  address_space       = ["10.0.0.0/16"]
  dns_servers         = []

  subnet {
    name           = "default"
    address_prefix = "10.0.1.0/24"
    security_group = azurerm_network_security_group.demo.id
  }

  subnet {
    name           = "penp"
    address_prefix = "10.0.2.0/24"
    security_group = azurerm_network_security_group.demo.id
  }

  tags = {
    environment = "test"
  }
}

resource "azurerm_subnet" "demo" {
  name                 = "sql-mi"
  resource_group_name  = azurerm_resource_group.demo.name
  virtual_network_name = azurerm_virtual_network.demo.name
  address_prefixes     = ["10.0.3.0/24"]

  delegation {
    name = "managedinstancedelegation"

    service_delegation {
      name    = "Microsoft.Sql/managedInstances"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action", "Microsoft.Network/virtualNetworks/subnets/prepareNetworkPolicies/action", "Microsoft.Network/virtualNetworks/subnets/unprepareNetworkPolicies/action"]
    }
  }
}

resource "azurerm_subnet_network_security_group_association" "demo" {
  subnet_id                 = azurerm_subnet.demo.id
  network_security_group_id = azurerm_network_security_group.demo.id
}

resource "azurerm_route_table" "demo" {
  name                          = format("%s-%s", "rt", replace(azurerm_resource_group.demo.name, "rg-", ""))
  location                      = azurerm_resource_group.demo.location
  resource_group_name           = azurerm_resource_group.demo.name
  disable_bgp_route_propagation = false

  route {
    name           = "route1"
    address_prefix = "0.0.0.0/0"
    next_hop_type  = "Internet"
  }

  depends_on = [
    azurerm_subnet.demo,
  ]
}

resource "azurerm_subnet_route_table_association" "demo" {
  subnet_id      = azurerm_subnet.demo.id
  route_table_id = azurerm_route_table.demo.id
}

resource "azurerm_storage_account" "demo" {
  name                          = format("%s%s", "stacc", random_string.random.result)
  resource_group_name           = azurerm_resource_group.demo.name
  location                      = azurerm_resource_group.demo.location
  account_tier                  = "Standard"
  account_replication_type      = "LRS"
  account_kind                  = "StorageV2"
  is_hns_enabled                = true
  public_network_access_enabled = false

  tags = {
    environment = "test"
  }
}

resource "azurerm_storage_data_lake_gen2_filesystem" "demo" {
  name               = "fs-demo"
  storage_account_id = azurerm_storage_account.demo.id
}

resource "azurerm_private_dns_zone" "demo" {
  for_each = toset([
    "privatelink.blob.core.windows.net",
    "privatelink.dfs.core.windows.net",
    "privatelink.vaultcore.azure.net",
    "privatelink.sql.azuresynapse.net",
    "privatelink.dev.azuresynapse.net"
  ])
  name                = each.key
  resource_group_name = azurerm_resource_group.demo.name

  tags = {
    environment = "test"
  }
}

resource "azurerm_private_dns_zone_virtual_network_link" "demo" {
  for_each              = azurerm_private_dns_zone.demo
  name                  = replace(each.key, ".", "")
  resource_group_name   = azurerm_resource_group.demo.name
  private_dns_zone_name = azurerm_private_dns_zone.demo[each.key].name
  virtual_network_id    = azurerm_virtual_network.demo.id
}

locals {
  network_security_rule = {
    allow_management_inbound = {
      priority                   = 106
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_ranges    = ["9000", "9003", "1438", "1440", "1452"]
      source_address_prefix      = "*"
      destination_address_prefix = "*"
    }
    allow_misubnet_inbound = {
      priority                   = 200
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "*"
      source_port_range          = "*"
      destination_port_range     = "*"
      source_address_prefix      = "10.0.0.0/24"
      destination_address_prefix = "*"
    }
    allow_health_probe_inbound = {
      priority                   = 300
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "*"
      source_port_range          = "*"
      destination_port_range     = "*"
      source_address_prefix      = "AzureLoadBalancer"
      destination_address_prefix = "*"
    }
    allow_tds_inbound = {
      priority                   = 1000
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "1433"
      source_address_prefix      = "VirtualNetwork"
      destination_address_prefix = "*"
    }
    deny_all_inbound = {
      priority                   = 4096
      direction                  = "Inbound"
      access                     = "Deny"
      protocol                   = "*"
      source_port_range          = "*"
      destination_port_range     = "*"
      source_address_prefix      = "*"
      destination_address_prefix = "*"
    }
    allow_management_outbound = {
      priority                   = 102
      direction                  = "Outbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_ranges    = ["80", "443", "12000"]
      source_address_prefix      = "*"
      destination_address_prefix = "*"
    }
    allow_misubnet_outbound = {
      priority                   = 200
      direction                  = "Outbound"
      access                     = "Allow"
      protocol                   = "*"
      source_port_range          = "*"
      destination_port_range     = "*"
      source_address_prefix      = "10.0.0.0/24"
      destination_address_prefix = "*"
    }
    deny_all_outbound = {
      priority                   = 4096
      direction                  = "Outbound"
      access                     = "Deny"
      protocol                   = "*"
      source_port_range          = "*"
      destination_port_range     = "*"
      source_address_prefix      = "*"
      destination_address_prefix = "*"
    }
  }
  private_endpoint = {
    sto-blob = {
      subresource_names              = ["blob"]
      private_dns_zone_ids           = azurerm_private_dns_zone.demo["privatelink.blob.core.windows.net"].id
      private_connection_resource_id = azurerm_storage_account.demo.id
    }
    sto-dfs = {
      subresource_names              = ["dfs"]
      private_dns_zone_ids           = azurerm_private_dns_zone.demo["privatelink.dfs.core.windows.net"].id
      private_connection_resource_id = azurerm_storage_account.demo.id
    }
    kv-vault = {
      subresource_names              = ["vault"]
      private_dns_zone_ids           = azurerm_private_dns_zone.demo["privatelink.vaultcore.azure.net"].id
      private_connection_resource_id = azurerm_key_vault.demo.id
    }
    synapse-sql = {
      subresource_names              = ["sql"]
      private_dns_zone_ids           = azurerm_private_dns_zone.demo["privatelink.sql.azuresynapse.net"].id
      private_connection_resource_id = azurerm_synapse_workspace.demo.id
    }
    synapse-sql-ondemand = {
      subresource_names              = ["sqlOnDemand"]
      private_dns_zone_ids           = azurerm_private_dns_zone.demo["privatelink.sql.azuresynapse.net"].id
      private_connection_resource_id = azurerm_synapse_workspace.demo.id
    }
    synapse-dev = {
      subresource_names              = ["dev"]
      private_dns_zone_ids           = azurerm_private_dns_zone.demo["privatelink.dev.azuresynapse.net"].id
      private_connection_resource_id = azurerm_synapse_workspace.demo.id
    }

  }

  role_assignment = {
    kv = {
      scope                = azurerm_key_vault.demo.id
      role_definition_name = "Key Vault Administrator"
      principal_id         = data.azurerm_client_config.current.object_id
    }
    sid-synapse-kv = {
      scope                = azurerm_key_vault.demo.id
      role_definition_name = "Key Vault Secrets User"
      principal_id         = azurerm_synapse_workspace.demo.identity[0].principal_id
    }
    sid-synapse-stacc = {
      scope                = azurerm_storage_account.demo.id
      role_definition_name = "Storage Blob Data Contributor"
      principal_id         = azurerm_synapse_workspace.demo.identity[0].principal_id
    }
  }

  kv_secret = {
    sql-cred = {
      kv_value = random_string.spe_random.result
    }
    sql-min-cred = {
      kv_value = random_string.spe_random.result
    }
  }

  vnet_subnets = { for key, value in azurerm_virtual_network.demo.subnet : "${key.name}" => key.id }
}

output "name" {
  value = local.vnet_subnets
}

resource "azurerm_private_endpoint" "demo" {
  for_each            = local.private_endpoint
  name                = "penp-${each.key}"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name
  subnet_id           = local.vnet_subnets["penp"]

  private_service_connection {
    name                           = "${each.key}-demo-connection"
    private_connection_resource_id = each.value.private_connection_resource_id
    subresource_names              = each.value.subresource_names
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "${each.key}-dns-zone-group"
    private_dns_zone_ids = [each.value.private_dns_zone_ids]
  }

  tags = {
    environment = "test"
  }
}

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "demo" {
  name                          = format("%s-%s", "kv", replace(azurerm_resource_group.demo.name, "rg-", ""))
  location                      = azurerm_resource_group.demo.location
  resource_group_name           = azurerm_resource_group.demo.name
  enabled_for_disk_encryption   = true
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days    = 7
  purge_protection_enabled      = false
  enable_rbac_authorization     = true
  sku_name                      = "standard"
  public_network_access_enabled = false

  tags = {
    environment = "test"
  }
}

resource "azurerm_role_assignment" "demo" {
  for_each             = local.role_assignment
  scope                = each.value.scope
  role_definition_name = each.value.role_definition_name
  principal_id         = each.value.principal_id
}

resource "azurerm_key_vault_secret" "demo" {
  for_each     = local.kv_secret
  name         = each.key
  value        = each.value.kv_value
  key_vault_id = azurerm_key_vault.demo.id

  tags = {
    environment = "test"
  }
}

resource "azurerm_synapse_workspace" "demo" {
  name                                 = format("%s-%s", "sywks", replace(azurerm_resource_group.demo.name, "rg-", ""))
  resource_group_name                  = azurerm_resource_group.demo.name
  location                             = azurerm_resource_group.demo.location
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.demo.id
  sql_administrator_login              = "sqladminuser"
  sql_administrator_login_password     = azurerm_key_vault_secret.demo["sql-cred"].value
  managed_virtual_network_enabled      = true
  public_network_access_enabled        = false

  identity {
    type = "SystemAssigned"
  }

  tags = {
    environment = "test"
  }
}

resource "azurerm_synapse_workspace_aad_admin" "demo" {
  synapse_workspace_id = azurerm_synapse_workspace.demo.id
  login                = "AzureAD Admin"
  object_id            = data.azurerm_client_config.current.object_id
  tenant_id            = data.azurerm_client_config.current.tenant_id
}

resource "azurerm_sql_managed_instance" "demo" {
  name                         = format("%s-%s", "sqlmin", replace(azurerm_resource_group.demo.name, "rg-", ""))
  resource_group_name          = azurerm_resource_group.demo.name
  location                     = azurerm_resource_group.demo.location
  administrator_login          = "sqlminadminuser"
  administrator_login_password = azurerm_key_vault_secret.demo["sql-min-cred"].value
  license_type                 = "BasePrice"
  subnet_id                    = azurerm_subnet.demo.id
  sku_name                     = "GP_Gen5"
  vcores                       = 4
  storage_size_in_gb           = 32

  depends_on = [
    azurerm_subnet_network_security_group_association.demo,
    azurerm_subnet_route_table_association.demo,
  ]
}
