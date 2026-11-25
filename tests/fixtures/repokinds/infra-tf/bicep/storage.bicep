resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'acmedata'
  location: 'westeurope'
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: true
    supportsHttpsTrafficOnly: true
  }
}
