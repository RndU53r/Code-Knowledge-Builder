// Azure DR site for the shop (fixture; never deploy)
param location string = resourceGroup().location

resource reports 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'shopreportsfixture'
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: true
    minimumTlsVersion: 'TLS1_0'
    supportsHttpsTrafficOnly: false
  }
}

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {
  name: 'gateway-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-any'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'Internet'
          destinationPortRange: '3000'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}
