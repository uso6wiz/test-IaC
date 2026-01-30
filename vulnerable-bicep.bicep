// IaC スキャンテスト用 - 意図的に脆弱な構成（本番適用禁止）
// Checkov, Terrascan, Snyk IaC 等で検出される想定のパターンを含む

@description('脆弱なストレージアカウント名')
param storageAccountName string = 'vulnteststoragepublic'

@secure()
@description('VM 管理者パスワード')
param adminPassword string

@description('❌ 平文デフォルトの SQL パスワード')
param sqlAdminPassword string = 'P@ssw0rd123!'

@description('❌ ハードコードされたシークレット')
param apiKey string = 'sk-live-azure-hardcoded-secret'

param location string = resourceGroup().location

// ❌ 変数に平文の接続文字列・シークレット
var vulnConnectionString = 'Server=tcp:sqlserver;Database=db;User ID=sa;Password=P@ssw0rd123!;'
var vulnApiKey = 'sk-prod-12345-exposed-key'

// ========== ネットワーク（VM/App 依存用） ==========
resource vulnVnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: 'vuln-vnet'
  location: location
  properties: {
    addressSpace: { addressPrefixes: ['10.0.0.0/16'] }
    subnets: [{ name: 'default', properties: { addressPrefix: '10.0.1.0/24' } }]
  }
}

resource vulnNic 'Microsoft.Network/networkInterfaces@2023-05-01' = {
  name: 'vuln-nic'
  location: location
  properties: {
    ipConfigurations: [{
      name: 'ipconfig1'
      properties: {
        subnet: { id: '${vulnVnet.id}/subnets/default' }
        privateIPAllocationMethod: 'Dynamic'
      }
    }]
  }
}

resource vulnAsp 'Microsoft.Web/serverfarms@2022-09-01' = {
  name: 'vuln-asp'
  location: location
  sku: { name: 'B1', tier: 'Basic' }
  kind: 'app'
  properties: { reserved: false }
}

// ========== Storage Account 脆弱性 ==========
resource vulnStorage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  sku: { name: 'Standard_LRS', tier: 'Standard' }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: true
    minimumTlsVersion: 'TLS1_0'
    supportsHttpsTrafficOnly: false
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
      ipRules: []
    }
    encryption: {
      services: { blob: { enabled: true }, file: { enabled: true } }
      keySource: 'Microsoft.Storage'
    }
  }
}

// ========== NSG 脆弱性 ==========
resource vulnNsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'vuln-nsg-all-open'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowSSH'
        properties: {
          priority: 100
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
      {
        name: 'AllowRDP'
        properties: {
          priority: 110
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '0.0.0.0/0'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '3389'
        }
      }
      {
        name: 'AllowAllInbound'
        properties: {
          priority: 120
          protocol: '*'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

// ========== SQL Server 脆弱性 ==========
resource vulnSqlServer 'Microsoft.Sql/servers@2023-05-01-preview' = {
  name: 'vuln-sql-server-iac-test'
  location: location
  properties: {
    administratorLogin: 'sqladmin'
    administratorLoginPassword: sqlAdminPassword
    version: '12.0'
    publicNetworkAccess: 'Enabled'
    minimalTlsVersion: '1.0'
  }
}

resource vulnSqlFirewall 'Microsoft.Sql/servers/firewallRules@2023-05-01-preview' = {
  parent: vulnSqlServer
  name: 'AllowAllAzureAndInternet'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '255.255.255.255'
  }
}

// ========== Key Vault 脆弱性 ==========
resource vulnKeyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'vuln-kv-iac-test'
  location: location
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: subscription().tenantId
    enableRbacAuthorization: false
    enableSoftDelete: false
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
      ipRules: []
    }
    accessPolicies: [
      {
        tenantId: subscription().tenantId
        objectId: '00000000-0000-0000-0000-000000000000'
        permissions: {
          secrets: ['get', 'list', 'set', 'delete', 'backup', 'restore', 'recover', 'purge']
          keys: ['get', 'list', 'create', 'delete', 'update', 'encrypt', 'decrypt', 'sign', 'verify', 'wrapKey', 'unwrapKey']
          certificates: ['get', 'list', 'create', 'delete', 'update', 'managecontacts', 'getissuers', 'listissuers', 'setissuers', 'deleteissuers', 'manageissuers', 'recover', 'purge']
        }
      }
    ]
  }
}

// ========== VM 脆弱性 ==========
resource vulnVm 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name: 'vuln-vm-iac-test'
  location: location
  properties: {
    hardwareProfile: { vmSize: 'Standard_B1s' }
    osProfile: {
      computerName: 'vulnvm'
      adminUsername: 'azureuser'
      adminPassword: adminPassword
      windowsConfiguration: {
        provisionVMAgent: true
        enableAutomaticUpdates: false
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: '2019-Datacenter'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        diskSizeGB: 128
        managedDisk: { storageAccountType: 'Standard_LRS' }
      }
    }
    networkProfile: {
      networkInterfaces: [{ id: vulnNic.id, properties: { deleteOption: 'Delete' } }]
    }
  }
}

// ========== App Service 脆弱性 ==========
resource vulnWebApp 'Microsoft.Web/sites@2022-09-01' = {
  name: 'vuln-app-iac-test'
  location: location
  kind: 'app'
  properties: {
    serverFarmId: vulnAsp.id
    httpsOnly: false
    siteConfig: {
      minTlsVersion: '1.0'
      ftpsState: 'AllAllowed'
      http20Enabled: false
      appSettings: [
        { name: 'API_KEY', value: apiKey }
        { name: 'DB_CONNECTION_STRING', value: vulnConnectionString }
        { name: 'SECRET_TOKEN', value: vulnApiKey }
      ]
    }
  }
}

// ========== AKS 脆弱性 ==========
resource vulnAks 'Microsoft.ContainerService/managedClusters@2023-10-01' = {
  name: 'vuln-aks-iac-test'
  location: location
  properties: {
    dnsPrefix: 'vulnaks'
    agentPoolProfiles: [
      {
        name: 'default'
        count: 1
        vmSize: 'Standard_B2s'
        osType: 'Linux'
        type: 'VirtualMachineScaleSets'
      }
    ]
    enableRbac: false
    networkProfile: {
      networkPlugin: 'kubenet'
      loadBalancerSku: 'Basic'
    }
    apiServerAccessProfile: {
      enablePrivateCluster: false
    }
    addonProfiles: {
      omsagent: { enabled: false }
    }
  }
}

// ========== Redis 脆弱性 ==========
resource vulnRedis 'Microsoft.Cache/redis@2023-08-01' = {
  name: 'vuln-redis-iac-test'
  location: location
  properties: {
    sku: { name: 'Basic', family: 'C', capacity: 0 }
    enableNonSslPort: true
    minimumTlsVersion: '1.0'
    publicNetworkAccess: 'Enabled'
  }
}

// ========== Cosmos DB 脆弱性 ==========
resource vulnCosmos 'Microsoft.DocumentDB/databaseAccounts@2023-09-15' = {
  name: 'vuln-cosmos-iac-test'
  location: location
  kind: 'GlobalDocumentDB'
  properties: {
    databaseAccountOfferType: 'Standard'
    publicNetworkAccess: 'Enabled'
    enableFreeTier: true
    consistencyPolicy: { defaultConsistencyLevel: 'Session' }
    locations: [{ locationName: location, failoverPriority: 0 }]
  }
}

// ========== Outputs ==========
output storageAccountName string = storageAccountName
output keyVaultName string = vulnKeyVault.name
