#! /bin/pwsh

<#

    Purpose:  Exports all objects from a subscription to a local directory

#>



$BackupDir     = $($env:DIRECTORY)

$resourcegroup = $($env:RESOURCEGROUPNAME)

$subscription  = $($env:SUBSCRIPTION)
$tenant        = $($env:TENANT)
$scope         = $($env:SCOPE)
$appid         = ${env:MAPPED_APP_ID}
$secret        = ${env:MAPPED_APP_SECRET}


<#
  Set the various object types to 1 for a backup to occur
#>

$Backup_SubscriptionObjects = 1

$Backup_RoleDefinitions = 0
$Backup_ResourceGroupDetails = 0
$Backup_RoleAssignments = 0
$Backup_PolicySetDefinitions = 0
$Backup_PolicyDefinitions = 0
$Backup_PolicyAssignments = 0
$Backup_PolicyExemptions = 0
$Backup_SecurityCenteSubscriptions = 0



$DebugPreference = 'Continue' # Enable to create debug logging


if ($($env:DIRECTORY)){$rootDir   = $($env:DIRECTORY)}



# Determine if script is being run on linux or windows by the direction
# of slashed in the PATH statement
if ((Get-ChildItem Env:PATH).Value -Match '/'){ $OS='linux'}else{$OS='win'}

# Create a slash variable based on the OS type of the host
if($OS -eq 'win' ) { $slash = "\" }
if($OS -eq 'linux'){ $slash = "/"}

$ScriptDir  = Split-Path $script:MyInvocation.MyCommand.Path


 $BackupDir = "$($rootDir)$($slash)json"
 $ReportDir = "$($rootDir)$($slash)reports"
 $ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
 $ModuleDir = "$($ScriptDir)$($slash)modules"


Import-Module "$($moduledir)$($slash)AZRest$($slash)AZRest.psm1" | write-debug

write-debug "tenant = $tenant "
write-debug "Backupdir = $BackupDir"
write-debug "ReportDir = $ReportDir"
write-debug "ScriptDir = $ScriptDir"
write-debug "ModuleDir = $ModuleDir"




function Clean-AzureObject(){
<#
    Purpose:  Parsing function to remove read only properties from an object so the exported defintion may be used for redeployment
              Not neceassry for a basic audit.

              Also provides the ability to perform additional GET against specific object types

#>
    [CmdletBinding()]
    param(
        [Parameter(mandatory=$true)]
        [string]$azobjectjson,
        [Parameter(mandatory=$true)]
        [string]$BackupDir,
        [Parameter(mandatory=$true)]
        [Hashtable]$AzAPIVersions,
        [Parameter(mandatory=$true)]
        [Hashtable]$authHeader
    )

    $azobject = ConvertFrom-Json $azobjectjson

    # Remove common properties
    if ($azobject.PSObject.properties -match 'etag'){$azobject.PSObject.properties.remove('etag')}

write-debug "(function Clean-AzureObject) started with type $($azobject.type)"

    switch($azobject.type){
       "Microsoft.ApiManagement/service" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
            ($azobject.properties).PSObject.properties.remove('CreatedAtUTC')
       }
       "Microsoft.Automation/AutomationAccounts" {
            ($azobject.properties).PSObject.properties.remove('state')
            ($azobject.properties).PSObject.properties.remove('creationTime')
            ($azobject.properties).PSObject.properties.remove('lastModifiedBy')
            ($azobject.properties).PSObject.properties.remove('lastModifiedTime')

       }
       "Microsoft.Automation/AutomationAccounts/Runbooks" {
            ($azobject.properties).PSObject.properties.remove('creationTime')
            ($azobject.properties).PSObject.properties.remove('lastModifiedBy')
            ($azobject.properties).PSObject.properties.remove('lastModifiedTime')
            ($azobject.properties).PSObject.properties.remove('provisioningState')
       }
       "Microsoft.Cache/Redis" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
       }
       "Microsoft.Compute/virtualMachines/extensions" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
       }
       "Microsoft.Compute/virtualMachines" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
            ($azobject.properties).PSObject.properties.remove('vmId')
            ($azobject.identity).PSObject.properties.remove('principalId')
            ($azobject.identity).PSObject.properties.remove('tenantId')
            #
            ($azobject.properties.osProfile).PSObject.properties.remove('requireGuestProvisionSignal')

            #Disks will be managed separately & before the VM.  Disk option attach will need to be used.
            #more work will be needed to accomodate data disks
            ($azobject.properties.storageProfile.osDisk.managedDisk).PSObject.properties.remove('id')


          #  # Handle each vm extension
          #  For ($i=0; $i -le ($azobject.resources.Count -1); $i++) {
          #      $null = Invoke-azobjectbackup -Id $azobject.resources[$i].id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
          #  }
          #  $azobject.resources=@()


       }
       "Microsoft.Compute/disks" {
            ($azobject.properties).PSObject.properties.remove('timeCreated')
            ($azobject.properties).PSObject.properties.remove('provisioningState')
            ($azobject.properties).PSObject.properties.remove('uniqueId')
            ($azobject.properties).PSObject.properties.remove('diskSizeBytes')
       }

       "Microsoft.ContainerInstance/containerGroups" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
       }
       "Microsoft.DataFactory/factories" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
            ($azobject.properties).PSObject.properties.remove('createTime')
       }
       "Microsoft.DesktopVirtualization/applicationgroups" {
            ($azobject.properties).PSObject.properties.remove('objectId')
       }
       "Microsoft.DocumentDB/databaseAccounts" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
            ($azobject.systemData).PSObject.properties.remove('createdAt')

            # Handle any Private Endpoint Connection as separate objects
            # catch elements without Private Endpoints
            try{
              For ($i=0; $i -le ($azobject.properties.PrivateEndpointConnections.Count -1); $i++) {
                  $null = Invoke-azobjectbackup -Id $azobject.properties.PrivateEndpointConnections[$i].id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
              }
            $azobject.properties.PrivateEndpointConnections=@()
            }catch{
              write-warning "PrivateEndpointConnections not available on obtect Microsoft.DocumentDB/databaseAccounts"
            }

       }
       "Microsoft.EventHub" {
            ($azobject.properties).PSObject.properties.remove('createdAt')
            ($azobject.properties).PSObject.properties.remove('updatedAt')
       }
       "Microsoft.EventHub/clusters" {
            ($azobject.properties).PSObject.properties.remove('createdAt')
            ($azobject.properties).PSObject.properties.remove('updatedAt')
       }
       "Microsoft.EventHub/Namespaces" {
            ($azobject.properties).PSObject.properties.remove('createdAt')
            ($azobject.properties).PSObject.properties.remove('updatedAt')
            ($azobject.properties).PSObject.properties.remove('provisioningState')

            # Handle any Private Endpoint Connection as separate objects
            # catch elements without Private Endpoints
            try{
              For ($i=0; $i -le ($azobject.properties.PrivateEndpointConnections.Count -1); $i++) {
                  $null = Invoke-azobjectbackup -Id $azobject.properties.PrivateEndpointConnections[$i].id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
              }
            $azobject.properties.PrivateEndpointConnections=@()
            }catch{
              write-warning "PrivateEndpointConnections not available on obtect Microsoft.EventHub/Namespaces"
            }

            #Grab any Event Hub details
            $queryuri = "https://management.azure.com/$($azobject.id)/eventhubs?api-version=2024-01-01"
            $response =  $null
            $response = Invoke-RestMethod -Uri $queryuri -Method GET -Headers $authHeader
             foreach ($eventhub in $response.value ){
              $null = Invoke-azobjectbackup -Id $eventhub.id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
            }

            #Grab any Consumer Groups details
            $queryuri = "https://management.azure.com/$($azobject.id)/consumergroups?api-version=2024-01-01"
            $response =  $null
            $response = Invoke-RestMethod -Uri $queryuri -Method GET -Headers $authHeader
             foreach ($eventhub in $response.value ){
              $null = Invoke-azobjectbackup -Id $eventhub.id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
            }


       }
       "Microsoft.EventHub/Namespaces/PrivateEndpointConnections" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')

       }
       "Microsoft.HybridCompute/machines" {
            ($azobject.properties).PSObject.properties.remove('lastStatusChange')
            ($azobject.identity).PSObject.properties.remove('principalId')
       }
       "microsoft.insights/components" {
            ($azobject.properties).PSObject.properties.remove('CreationDate')
            ($azobject.properties).PSObject.properties.remove('provisioningState')
       }
       "Microsoft.Insights/scheduledqueryrules" {
            ($azobject).PSObject.properties.remove('systemData')
       }
       "Microsoft.Insights/workbooks" {
       }
       "Microsoft.KeyVault/vaults" {
            $azobject.PSObject.properties.remove('systemData')
            ($azobject.properties).PSObject.properties.remove('provisioningState')
            try{
              For ($i=0; $i -le ($azobject.properties.PrivateEndpointConnections.Count -1); $i++) {
                  $null = Invoke-azobjectbackup -Id $azobject.properties.PrivateEndpointConnections[$i].id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
              }
            }catch{
              write-warning "PrivateEndpointConnections not available on obtect Microsoft.KeyVault/vaults"
            }
       }
       "Microsoft.Kusto/Clusters" {
            ($azobject).PSObject.properties.remove('etag')

                # clusters have databases
                $children=@(
                    "/databases"
                )

                foreach ($child in $children){
                    write-debug "Microsoft.Kusto/Clusters ---  Get-AzureObject -id $($azobject.Id)$($child) "
                    $response = Get-AzureObject -id "$($azobject.Id)$($child)" -authHeader  $authHeader -apiversions $AzAPIVersions

                   foreach ($element in $response.value){
                        write-debug "Microsoft.Kusto/Clusters --- /databases Invoke-azobjectbackup -Id $element.id"
                         $null = Invoke-azobjectbackup -Id $element.id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
                         #Get Data Connections too
                         write-debug "Microsoft.Kusto/Clusters --- dataConnections Get-AzureObject -Id $($element.id)/dataConnections"
                         $dconnections = Get-AzureObject -Id "$($element.id)/dataConnections" -authHeader  $authHeader -apiversions $AzAPIVersions
                         foreach ($dc in $dconnections.value){
                            write-debug "Microsoft.Kusto/Clusters --- dataConnections Invoke-azobjectbackup -Id $($dc.id)"
                            $null = Invoke-azobjectbackup -Id $dc.id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
                            write-debug "Microsoft.Kusto/Clusters --- Backup of $($dc.id) complete"
                         }
                  }
                }


       }
       "Microsoft.Logic/workflows" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
            ($azobject.properties).PSObject.properties.remove('createdTime')
            ($azobject.properties).PSObject.properties.remove('changedTime')
            ($azobject.properties).PSObject.properties.remove('endpointsConfiguration')
            ($azobject.properties).PSObject.properties.remove('version')
       }
       "Microsoft.MachineLearningServices/workspaces" {
            $azobject.PSObject.properties.remove('etag')
 #           ($azobject.identity).PSObject.properties.remove('principalId')
 #           ($azobject.identity).PSObject.properties.remove('tenantId')
            ($azobject.systemData).PSObject.properties.remove('createdAt')
            ($azobject.systemData).PSObject.properties.remove('createdBy')
            ($azobject.systemData).PSObject.properties.remove('createdByType')
            ($azobject.systemData).PSObject.properties.remove('lastModifiedAt')
            ($azobject.systemData).PSObject.properties.remove('lastModifiedBy')
            ($azobject.systemData).PSObject.properties.remove('lastModifiedByType')
            ($azobject.systemData).PSObject.properties.remove('provisioningState')
       }
       "Microsoft.Network/loadBalancers" {
            $azobject.PSObject.properties.remove('etag')
            ($azobject.properties).PSObject.properties.remove('provisioningState')

            # Handle each nat rule as separate objects
            For ($i=0; $i -le ($azobject.properties.inboundNatRules.Count -1); $i++) {
                $null = Invoke-azobjectbackup -Id $azobject.properties.inboundNatRules[$i].id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
               #  ($azobject.properties.inboundNatRules[$i]).PSObject.properties.remove('etag')
               #  ($azobject.properties.inboundNatRules[$i].properties).PSObject.properties.remove('provisioningState')
            }

            # Handle each frontendIPConfigurations as separate objects
            For ($i=0; $i -le ($azobject.properties.frontendIPConfigurations.Count -1); $i++) {
                $null = Invoke-azobjectbackup -Id $azobject.properties.frontendIPConfigurations[$i].id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
            }

            # Handle each backendAddressPools as separate objects
            For ($i=0; $i -le ($azobject.properties.backendAddressPools.Count -1); $i++) {
                $null = Invoke-azobjectbackup -Id $azobject.properties.backendAddressPools[$i].id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
            }

            # Handle each loadBalancingRules as separate objects
            For ($i=0; $i -le ($azobject.properties.loadBalancingRules.Count -1); $i++) {
                $null = Invoke-azobjectbackup -Id $azobject.properties.loadBalancingRules[$i].id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
            }

            # Handle each probes as separate objects
            For ($i=0; $i -le ($azobject.properties.probes.Count -1); $i++) {
                $null = Invoke-azobjectbackup -Id $azobject.properties.probes[$i].id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
            }

       }
       "Microsoft.Network/networkInterfaces" {
            $azobject.PSObject.properties.remove('etag')
            ($azobject.properties).PSObject.properties.remove('provisioningState')
            ($azobject.properties).PSObject.properties.remove('resourceGuid')
            ($azobject.properties).PSObject.properties.remove('macAddress')

            # IP Configurations must exist in a Network interface for deployment
            # Clean inplace
            # duplicate with export to aid auditing
            For ($i=0; $i -le ($azobject.properties.ipConfigurations.Count -1); $i++) {
                ($azobject.properties.ipConfigurations[$i].properties).PSObject.properties.remove('provisioningState')
                ($azobject.properties.ipConfigurations[$i]).PSObject.properties.remove('etag')
                #export as well
                $null = Invoke-azobjectbackup -Id $azobject.properties.ipConfigurations[$i].id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
            }

       }
       "Microsoft.Network/loadBalancers/inboundNatRules" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
       }
       "Microsoft.Network/networkInterfaces/ipConfigurations" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
       }
       "Microsoft.Network/networkProfiles" {
            $azobject.PSObject.properties.remove('etag')
            ($azobject.properties).PSObject.properties.remove('provisioningState')
            # Clean inplace
            For ($i=0; $i -le ($azobject.properties.containerNetworkInterfaceConfigurations.Count -1); $i++) {
                ($azobject.properties.containerNetworkInterfaceConfigurations[$i].properties).PSObject.properties.remove('provisioningState')
                ($azobject.properties.containerNetworkInterfaceConfigurations[$i]).PSObject.properties.remove('etag')
            }
            For ($i=0; $i -le ($azobject.properties.containerNetworkInterfaces.Count -1); $i++) {
                ($azobject.properties.containerNetworkInterfaces[$i].properties).PSObject.properties.remove('provisioningState')
                ($azobject.properties.containerNetworkInterfaces[$i]).PSObject.properties.remove('etag')
            }
       }



       "Microsoft.Network/networkSecurityGroups" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
            ($azobject.properties).PSObject.properties.remove('resourceGuid')

            # Handle each security rule as separate objects
            For ($i=0; $i -le ($azobject.properties.securityRules.Count -1); $i++) {
               # $null = Invoke-azobjectbackup -Id $azobject.properties.securityRules[$i].id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
                 ($azobject.properties.SecurityRules[$i]).PSObject.properties.remove('etag')
                 ($azobject.properties.SecurityRules[$i].properties).PSObject.properties.remove('provisioningState')
            }
            #$azobject.properties.securityRules=@()

            # Handle each default security rules - must be part of the nsg
            # questions if some objects (like nsg rules shouldnt be separated for deployment
            # Just clean the rules in place
            For ($i=0; $i -le ($azobject.properties.defaultSecurityRules.Count -1); $i++) {
                 ($azobject.properties.defaultSecurityRules[$i]).PSObject.properties.remove('etag')
                 ($azobject.properties.defaultSecurityRules[$i].properties).PSObject.properties.remove('provisioningState')
            }
       }
       "Microsoft.Network/networkSecurityGroups/defaultSecurityRules" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
       }
       "Microsoft.Network/networkSecurityGroups/securityRules" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
       }

       "Microsoft.OperationalInsights/queryPacks" {
 #           ($azobject.properties).PSObject.properties.remove('provisioningState')

            # I need to preserve eack query in a pack as a distinct object
            $queryPackobjects  =@()

            $queryuri = "https://management.azure.com/$($azobject.id)/queries?api-version=2019-09-01&includeBody=true"

            # Get the first set of returned objects into an array
            # There are likely to be many pages worth - if so, the response will have a nextlink url
            $response             = Invoke-RestMethod -Uri $queryuri -Method GET -Headers $authHeader
            $queryPackobjects += $response.value

            while($response.nextLink)
            {
                # Grab any additional pages of objects recursively until no more nextlink responses exist
                $nextLink = $response.nextLink

                $response = Invoke-RestMethod -Uri $nextLink -Method GET -Headers $authHeader
                $queryPackobjects += $response.value
            }

            foreach ($query in $queryPackobjects){
              $null = Invoke-azobjectbackup -Id $query.id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
            }


       }
       # Sentinel
       "Microsoft.OperationsManagement/solutions" {
            if ($azobject.plan.product -eq "OMSGallery/SecurityInsights"){
                # Retrieve Sentinel Specific settings
                # This is a Sentinel Workspace and should have a number of elements backed up
                # Entity Queries and Entity Query Templates are enormous... not normally of benefit to backup
                $children=@(
                    "/providers/Microsoft.SecurityInsights/sourcecontrols",
                    "/providers/Microsoft.SecurityInsights/settings",
                    "/providers/Microsoft.SecurityInsights/alertRules",
                    "/providers/Microsoft.SecurityInsights/automationRules",
                    "/providers/Microsoft.SecurityInsights/dataConnectors"
                )
                   # Other potential Sentinel related objects may be added from below
                   # "/providers/Microsoft.SecurityInsights/alertRuleTemplates", #Far too many to backup
                   # "/providers/Microsoft.SecurityInsights/bookmarks",   #bookmarks are sensitive for hunting
                   # "/providers/Microsoft.SecurityInsights/entityQueryTemplates",
                   # "/providers/Microsoft.SecurityInsights/entityQueries"

                foreach ($child in $children){


                        try {
                            $response = Get-AzureObject -id "$($azobject.properties.workspaceResourceId)$($child)" -authHeader  $authHeader -apiversions $AzAPIVersions
                        }
                        catch {
                            Write-Error "Failed to retrieve Azure object: $_"
                            # Optionally handle the error further, such as logging or setting a default value
                            $response = $null
                        }
                    foreach ($element in $response.value){

                        try {
                            $null = Invoke-azobjectbackup -Id $element.id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
                        }
                        catch {
                            Write-Warning "Failed to retrieve Azure object: $_"
                            # Optionally handle the error further, such as logging or setting a default value
                            $azobject = $null
                        }
                   }
                }

            }

       }
       "Microsoft.Network/privateEndpoints" {
            $azobject.PSObject.properties.remove('etag')
            ($azobject.properties).PSObject.properties.remove('provisioningState')
            ($azobject.properties).PSObject.properties.remove('resourceGuid')

            # Handle each default service connections - must be part of the private endpoint
            # Just clean the rules in place
            For ($i=0; $i -le ($azobject.properties.privateLinkServiceConnections.Count -1); $i++) {
                 ($azobject.properties.privateLinkServiceConnections[$i]).PSObject.properties.remove('etag')
                 ($azobject.properties.privateLinkServiceConnections[$i].properties).PSObject.properties.remove('provisioningState')
            }
       }
       "Microsoft.Network/privateDnsZones" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
       }
       "Microsoft.Network/publicIPAddresses" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
            ($azobject.properties).PSObject.properties.remove('resourceGuid')
            ($azobject.properties).PSObject.properties.remove('ipAddress')
       }
       "Microsoft.Network/routeTables" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
            ($azobject.properties).PSObject.properties.remove('resourceGuid')
            # Handle routes as separate objects
            For ($i=0; $i -le ($azobject.properties.routes.Count -1); $i++) {
                $null = Invoke-azobjectbackup -Id $azobject.properties.routes[$i].id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
            }
            $azobject.properties.routes=@()
       }
       "Microsoft.Network/virtualNetworks" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
            ($azobject.properties).PSObject.properties.remove('resourceGuid')

            # Handle each subnet as separate objects
            For ($i=0; $i -le ($azobject.properties.subnets.Count -1); $i++) {
                $null = Invoke-azobjectbackup -Id $azobject.properties.subnets[$i].id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
            }
            $azobject.properties.subnets=@()

            # Handle vnet Peering separate objects
            For ($i=0; $i -le ($azobject.properties.virtualNetworkPeerings.Count -1); $i++) {
                $null = Invoke-azobjectbackup -Id $azobject.properties.virtualNetworkPeerings[$i].id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
            }
            $azobject.properties.virtualNetworkPeerings=@()
       }
       "Microsoft.Network/virtualNetworks/subnets" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
       }
       "Microsoft.Network/virtualNetworks/virtualNetworkPeerings" {
            $azobject.PSObject.properties.remove('etag')
            ($azobject.properties).PSObject.properties.remove('provisioningState')
            ($azobject.properties).PSObject.properties.remove('resourceGuid')
       }
       "Microsoft.OperationsManagement/solutions" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
            ($azobject.properties).PSObject.properties.remove('creationTime')
            ($azobject.properties).PSObject.properties.remove('lastModifiedTime')
       }
       "Microsoft.OperationalInsights/workspaces" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
            ($azobject.properties).PSObject.properties.remove('createdDate')
            ($azobject.properties).PSObject.properties.remove('modifiedDate')
            ($azobject.properties.sku).PSObject.properties.remove('lastSkuUpdate')
            ($azobject.properties.workspaceCapping).PSObject.properties.remove('quotaNextResetTime')

            # Try to capture Security EventCollection Configuration if the workspace is a security workspace
                 $children=@(
                    "/scopedPrivateLinkProxies",
                    "/query",
                    "/metadata",
                    "/dataSources/SecurityEventCollectionConfiguration",
                    "/linkedStorageAccounts",
                    "/tables",
                    "/storageInsightConfigs",
                    "/linkedServices",
                    "/dataExports",
                    "/savedSearches"
                )

                 $children=@(
                    "/savedSearches"
                )
                foreach ($child in $children){

                    try{
                      write-debug "Calling descended 'Microsoft.OperationalInsights/workspaces'  $($azobject.Id)$($child)"
                      $response = Get-AzureObject -id "$($azobject.Id)$($child)" -authHeader  $authHeader -apiversions $AzAPIVersions
                      write-debug "response = $(convertto-json -inputobject $response)"
                   }
                   catch{
                     write-warning "Get-AzureObject failed for ID $($azobject.Id)$($child)"
                   }
                   foreach ($element in $response.value){
                         $null = Invoke-azobjectbackup -Id $element.id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
                   }
                }


       }
       "Microsoft.Portal/dashboards" {

       }
       "Microsoft.RecoveryServices/vaults" {

         write-debug " Microsoft.RecoveryServices/vaults clean routine"

            try{
               ($azobject.properties).PSObject.properties.remove('provisioningState')
            }
            catch{
                write-warning "clean object provisioningState failed"
            }

            try{
               ($azobject.identity).PSObject.properties.remove('tenantId')
            }
            catch{
                write-warning "clean object tenantId failed"
            }

            try{
               ($azobject.identity).PSObject.properties.remove('principalId')
            }
            catch{
                write-warning "clean object principalId failed"
            }

            write-debug " Microsoft.RecoveryServices/vaults clean complete"


       }


       "Microsoft.Resources/resourceGroups" {
       }
       "Microsoft.SecurityInsights/alertRules" {
                $azobject.PSObject.properties.remove('etag')

                # All alert rules have actions
                $children=@(
                    "/actions"
                )

                foreach ($child in $children){
                    write-debug "Microsoft.SecurityInsights/alertRules ---  Get-AzureObject -id $($azobject.Id)$($child)"
                    $response = Get-AzureObject -id "$($azobject.Id)$($child)" -authHeader  $authHeader -apiversions $AzAPIVersions

                   foreach ($element in $response.value){
                        write-debug "Microsoft.SecurityInsights/alertRules --- child Invoke-azobjectbackup -Id $element.id"
                         $null = Invoke-azobjectbackup -Id $element.id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
                      }

                }

       }
       "Microsoft.Storage/storageAccounts" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
            ($azobject.properties).PSObject.properties.remove('creationTime')
            ($azobject.properties).PSObject.properties.remove('secondaryLocation')
            ($azobject.properties).PSObject.properties.remove('statusOfSecondary')

            # Handle any Private Endpoint Connection as separate objects
            # catch elements without Private Endpoints

            try{
              For ($i=0; $i -le ($azobject.properties.PrivateEndpointConnections.Count -1); $i++) {
                  $null = Invoke-azobjectbackup -Id $azobject.properties.PrivateEndpointConnections[$i].id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
              }
            }catch{
              write-warning "PrivateEndpointConnections not available on obtect Microsoft.Storage/storageAccounts"
            }

            #type containers need recursion if they exist
            #these may fail depending on the storage account
            try{
            $null = Invoke-azobjectbackup -Id "$($azobject.id)/blobServices/default" -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
            }
            catch{
                write-warning "Clean Microsoft.Storage/storageAccounts $($azobject.id)/blobServices/default failed $($Error[0].Exception.GetType().FullName)"
            }

            try{
            $null = Invoke-azobjectbackup -Id "$($azobject.id)/fileServices/default" -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
            }
            catch{
                write-warning "Clean Microsoft.Storage/storageAccounts $($azobject.id)/fileServices/default failed $($Error[0].Exception.GetType().FullName)"
            }

            try{
            $null = Invoke-azobjectbackup -Id "$($azobject.id)/queueServices/default" -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
            }
            catch{
                write-warning "Clean Microsoft.Storage/storageAccounts $($azobject.id)/queueServices/default failed $($Error[0].Exception.GetType().FullName)"
            }

            try{
            $null = Invoke-azobjectbackup -Id "$($azobject.id)/tableServices/default" -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
            }
            catch{
                write-warning "Clean Microsoft.Storage/storageAccounts $($azobject.id)/tableServices/default failed $($Error[0].Exception.GetType().FullName)"
            }
       }
       "Microsoft.SqlVirtualMachine/sqlVirtualMachines" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
       }
       "Microsoft.Web/connections" {
            ($azobject.properties).PSObject.properties.remove('provisioningState')
            ($azobject.properties).PSObject.properties.remove('createdTime')
            ($azobject.properties).PSObject.properties.remove('changedTime')
       }

    }
    write-debug "(function Clean-AzureObject) completing object clean function"
if ($azobject ){ convertto-json -InputObject $azobject -Depth 50}else{return $null}



}


function Invoke-azobjectbackup(){
<#
    Purpose:  Backs Up an Azure object onto the file system as a json object


#>
    [CmdletBinding()]
    param(
        [Parameter(mandatory=$true)]
        [string]$Id,
        [Parameter(mandatory=$true)]
        [string]$BackupDir,
        [Parameter(mandatory=$true)]
        [Hashtable]$AzAPIVersions,
        [Parameter(mandatory=$true)]
        [Hashtable]$authHeader,
        [Parameter(mandatory=$false)]
        [switch]$norecurse
    )

$object      = $null

write-debug "(function Invoke-azobjectbackup) -id $id"

try {
    $object = Get-Azureobject -AuthHeader $authHeader -apiversions $AzAPIVersions -id $id
}
catch {
    Write-Error "Failed to retrieve Azure object: $_"
    # Optionally handle the error further, such as logging or setting a default value
    $object = $null
}


#if($object.name){
#    $objectname = ($object.name).replace(' ','')
#}

$azobjectjson = $null

write-debug "Clean-AzureObject $id"


$objjson = $null
$objjson = convertto-json -InputObject $object -Depth 50


# Ensure object isnt empty
if($objjson){
write-debug "(function Invoke-azobjectbackup) Clean Object begin"
try {
      $azobjectjson = Clean-AzureObject -azobjectjson $objjson -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
}
catch {
    Write-Warning "Failed to clean Azure object: $_"
    # Optionally handle the error further, such as logging or setting a default value
    $azobjectjson = $objjson
}
write-debug "(function Invoke-azobjectbackup) Clean Object Complete"
}


# Split the Id string into an array so that different pieces can be retrieved
#$filename     = $Id.split('/')[-1]
$idarray      = $Id.Split("/")


# Delay requests to Microsoft Authorisation to prevent being throttled - Microsoft only all 120 a minute
if ($idarray[2] -eq "Microsoft.Authorization"){Start-Sleep -Milliseconds 500  }

# Objects will be written into folders based on their Resource Group unless they are special objects

write-debug "(function Invoke-azobjectbackup) Dirpath ResourceGroup = $dirpath"
$dirpath = "$($BackupDir)$($slash)$($idarray[4].ToLower())$($slash)"



# Keep all exported Policy Definitions together

if ($idarray[3] -eq "policyDefinitions"){$dirpath = "$($BackupDir)$($slash)policydefinitions$($slash)" }
if ($idarray[3] -eq "policySetDefinitions"){$dirpath = "$($BackupDir)$($slash)policyDefinition$($slash)"}

# Keep Security objects together

if ($idarray[4] -eq "Microsoft.Security"){$dirpath = "$($BackupDir)$($slash)Microsoft.Security$($slash)" }

#Role Assignments I want to keep with the objects
if ($object.type -eq "Microsoft.Authorization/roleAssignments" ){

    # The actual path will be the scope - not the object ID... either at the subscription level
    $dirpath = "$($BackupDir)$($slash)$($($object.properties.scope.split('/')[2]).ToLower())$($slash)roleAssignments$($slash)"
    # ... or at the Resource Group Level
    if ($object.properties.scope.split('/')[4]){$dirpath = "$($BackupDir)$($slash)$($($object.properties.scope.split('/')[4]).ToLower())$($slash)roleAssignments$($slash)" }
}






# Take special characters and spaces out of the backup file name
$backupfile = "$($idarray[8])"
#$backupfile = $backupfile.Replace(' ','')
#$backupfile = $backupfile.Replace('[','')
#$backupfile = $backupfile.Replace(']','')
#$backupfile = $backupfile.Replace(':','')
#$backupfile = $backupfile.Replace('\','-')
#$backupfile = $backupfile.Replace('/','-')

# Find the last 'provider' element
for ($i=0; $i -lt $IDArray.length; $i++) {
  if ($IDArray[$i] -eq 'providers'){$provIndex =  $i}
}

<#
   Backup file name gets messy
   Odd cases must be accounted for like virtual machine attached packages where many with the same names will exist in the
   same Resource Group.
   Others will have ids larger than the Windows character limit
   Normally just the object type plus its given name will be enough to be unique but exceptions must be accomodated

 #>


 # Because object types can be overloaded from root namespaces a bit of testing is required
  # to validate what the object type is.
  # The last provider element in the string is always the root namespace so we have to find
  # the last 'provider' element

   for ($i=0; $i -lt $IDArray.length; $i++) {
	   if ($IDArray[$i] -eq 'providers'){$provIndex =  $i}
   }

  # $provIndex references where the last occurence of 'provider' is in the Id string
  # we construct the resource type from stacking elements from the ID string

  $elementcount=1
  $providertype = @()


  # Starting at the provider, until the end of the string, stack each potential overload if it exists
  for ($i=$provIndex; $i -lt $IDArray.length; $i++) {
    switch($elementcount){
     {'2','3','5','7','9' -contains $_} { $providertype += $IDArray[$i]}
     default {}
    }
    $elementcount = $elementcount + 1
  }

  # We now know the object type
  #$objecttype  = $providertype -join "/"
  # Hack to reduce overall size of file names - just use the last element of object type
  $objecttype  = $providertype[-1]


if ($IDArray.length -lt 8 ){
    $outputfilename  = "$($IDArray[-1])__$($IDArray[-2])"
}
else{

        $outputfilename =  "$($objecttype)__`($($backupfile)`)__$($idarray[-1] )"
 #       if(!($objectname -eq $backupfile )){  $outputfilename = "$( $outputfilename)__`($($backupfile)`)"   }
}


# account for 260 character limitation with names of query rules
# truncate the file name
if ("$($dirpath)\$($outputfilename).json".Length -gt 259){

    $outputfilename = $outputfilename.Substring(0, 100)
    write-debug "(function Invoke-azobjectbackup) truncated backup file = $outputfilename"
}


# need to replace special characters in the file name

$outputfilename = $outputfilename.replace('[','(')
$outputfilename = $outputfilename.replace(']',')')
$outputfilename = $outputfilename.replace(':','-')
$outputfilename = $outputfilename.replace('\','-')
$outputfilename = $outputfilename.replace('/','-')
$outputfilename = $outputfilename.replace('|','-')

write-debug "(function Invoke-azobjectbackup) outfile = $($dirpath)$($outputfilename).json"



# White the output to file and probe for object types not listed by Microsoft
if ( $azobjectjson ){

    # If the directory doesnt exist, create it.
    if (!(Test-Path -Path $dirpath)){
      write-debug "creating directory $dirpath"
      $null = New-Item -Path $dirpath -ItemType 'Directory' -Force
    }

  # somewhere quoted null is being produced with workbooks?
  # hack to stop those files being written - only write json
  if ($azobjectjson.Contains('{')){

    write-debug "(function Invoke-azobjectbackup) azobjectjson contains {"
    write-debug "(function Invoke-azobjectbackup) out-File -FilePath $($dirpath)$( $outputfilename ).json"

    $null = Out-File -FilePath "$($dirpath)$( $outputfilename ).json" -InputObject $azobjectjson  -Force

    write-debug "(function Invoke-azobjectbackup) outfile written"


  }







# Skip diagnostics - its all legacy now & it was a nasty backup that was prone to failure
#
# if (!($norecurse)){
#        Invoke-DiagnosticsConfigSearch -Id $id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
#  }
}



}


function Invoke-DiagnosticsConfigSearch(){
<#
    Purpose:  Backs Up hidden Azure object onto the file system as a json objects
              Diagnostics Settings can only be determined by querying for a diagnostics settings file


#>
    [CmdletBinding()]
    param(
        [Parameter(mandatory=$true)]
        [string]$Id,
        [Parameter(mandatory=$true)]
        [string]$BackupDir,
        [Parameter(mandatory=$true)]
        [Hashtable]$AzAPIVersions,
        [Parameter(mandatory=$true)]
        [Hashtable]$authHeader
    )

# The objects to not look at for diagnostic logs
# This is largely redundant as I no longer back these up.

$ignoretypes=@(
"/",
"microsoft.alertsmanagement/smartdetectoralertrules",
"microsoft.authorization/policyassignments",
"Microsoft.Authorization/policyDefinitions",
"microsoft.authorization/policyexemptions",
"Microsoft.Authorization/policySetDefinitions",
"microsoft.authorization/roledefinitions",
"Microsoft.Authorization/roleAssignments",
"microsoft.automation/automationaccounts",
"microsoft.automation/automationaccounts/runbooks",
"microsoft.azureactivedirectory/b2cdirectories",
"microsoft.compute/availabilitysets",
"microsoft.compute/images",
"microsoft.compute/proximityplacementgroups",
"microsoft.compute/restorepointcollections",
"microsoft.compute/snapshots",
"microsoft.compute/sshpublickeys",
"microsoft.compute/virtualmachines/extensions",
"microsoft.hybridcompute/machines",
"Microsoft.Insights/ActivityLogAlerts",
"microsoft.insights/actiongroups",
"microsoft.insights/datacollectionendpoints",
"microsoft.insights/metricalerts",
"microsoft.insights/scheduledqueryrules",
"microsoft.insights/workbooks",
"Microsoft.MachineLearningServices/workspaces",
"microsoft.network/applicationsecuritygroups",
"microsoft.network/firewallpolicies",
"microsoft.network/networkinterfaces/ipconfigurations",
"microsoft.network/networkprofiles",
"microsoft.network/networkwatchers/flowlogs",
"microsoft.network/privatednszones/virtualnetworklinks",
"microsoft.network/routetables",
"microsoft.network/serviceendpointpolicies",
"microsoft.network/virtualhubs",
"microsoft.network/virtualnetworks/subnets",
"microsoft.network/virtualnetworks/virtualnetworkpeerings"
"microsoft.network/networkinterfaces/ipconfigurations",
"microsoft.network/privatednszones/virtualnetworklinks",
"microsoft.network/privatednszones/virtualnetworklinks",
"microsoft.operationsmanagement/solutions",
"microsoft.portal/dashboards",
"Microsoft.Resources/resourceGroups",
"Microsoft.SecurityInsights/sourcecontrols",
"Microsoft.SecurityInsights/settings",
"Microsoft.SecurityInsights/alertRules",
"Microsoft.SecurityInsights/automationRules",
"Microsoft.SecurityInsights/bookmarks",
"Microsoft.SecurityInsights/entityQueries",
"Microsoft.SecurityInsights/entityQueryTemplates",
"microsoft.solutions/applications",
"microsoft.sqlvirtualmachine/sqlvirtualmachines",
"microsoft.visualstudio/account",
"microsoft.web/connections"
)




$backup=$true

#write-debug "Hidden Object Id = $id"

$IDArray = ($id).split("/")

# Find the last 'provider' element
for ($i=0; $i -lt $IDArray.length; $i++) {
   if ($IDArray[$i] -eq 'providers'){$provIndex =  $i}
}

$arraykey = "$($IDArray[$provIndex + 1])/$($IDArray[$provIndex + 2])"
#write-debug $arraykey
write-debug "(function Invoke-DiagnosticsConfigSearch) ID = $($Id)"

# Ignore specifc types of objects that can't do diagnostic logging
if ($ignoretypes -contains $arraykey){
  #write-debug "found type in ignore array"
  $backup=$false
}

#Dont try and and get Diagnostics from a Resource Group
if ($IDArray.Count -eq 4 ){
  $backup=$false
}


if ($backup -eq $true){

  $object = $null
  write-debug "(function Invoke-DiagnosticsConfigSearch) diagnostics search $($arraykey)"

$object =    Get-Azureobject -AuthHeader $authHeader -apiversions $AzAPIVersions -id "$($id)/providers/microsoft.insights/diagnosticSettings/"

if ( $object.value){


    $azobjectjson = $null

    Foreach ($object in $object.value) {


         if (!($ignoretypes -contains $object.tyoe  )){
         write-debug "(function Invoke-DiagnosticsConfigSearch) Invoke-azobjectbackup -Id $($object.id) "
            $null = Invoke-azobjectbackup -Id $object.id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader -norecurse
         }

    }


#$filename = $Id.split('/')[-1]
$idarray=$Id.Split("/")
#Resource Group

# Force directory case notation to lower for consistency
$dirpath = "$($BackupDir)$($slash)$($idarray[4].ToLower())\"

if (!(Test-Path -Path $dirpath)){ New-Item -Path $dirpath -ItemType 'Directory' -Force   }

 write-debug "(function Invoke-DiagnosticsConfigSearch) $backupfile = $dirpath"
$backupfile = $dirpath
For ($i=($idarray.Count -3); $i -le ($idarray.Count -1); $i++) {

        if ($i -eq ($idarray.Count -3)){
                $backupfile = $backupfile + "$($idarray[$i])"
            }
        else
            {
                $backupfile = $backupfile + "__$($idarray[$i])"
        }

}

#Backup File will be an object filename representation within a RG directory structure
#$backupfile
$backupfile = $backupfile.Replace(' ','')

if ( $azobjectjson ){
    write-debug "(function Invoke-DiagnosticsConfigSearch) hidden object outfile = $backupfile"

    #account for 260 character limitation
    #truncate the file name
    if ("$($dirpath)\$($backupfile).json".Length -gt 259){

            $backupfile = $backupfile.Substring(0, 120)
    }

    write-debug "(function Invoke-DiagnosticsConfigSearch) Out-File -FilePath $($backupfile).json"

  Out-File -FilePath "$($backupfile).json" -InputObject $azobjectjson  -Force
}

} # object

}

}





<#

  Main

#>


# On some systems 'System.Web' needs to be explicitly added
Add-Type -AssemblyName System.Web;


try {
    # Get an authorised Azure Header
    $authHeader = Get-Header -scope $scope -Tenant $tenant -AppId $appid `
                             -secret $secret
}
catch {
    # Throw with the offending error message
    throw "Error occurred while getting the Azure Header: $($_.Exception.Message)"
}




<#

 Get all resources in a subscription (or just a Resource Group if specified)

 There are a number of hidden resources that will need to be grabbed later

#>

# If I'm not backing up just a Resource Group there are probably other elements I really need to get
if ($ResourceGroup){
    $queries=@(
            # Just Query Resource Group objects
            "https://management.azure.com/subscriptions/$($subscription)/resourceGroups/$($resourcegroup)/resources?api-version=2021-04-01"
    )
}
else
{
    $queries=@()

    # Get all Subscription objects
    if ($Backup_SubscriptionObjects -eq 1){
        $queries += "https://management.azure.com/subscriptions/$($subscription)/resources?api-version=2021-04-01"
    }

    # Role Definitions
    if ($Backup_RoleDefinitions -eq 1){
        $queries += "https://management.azure.com/subscriptions/$($subscription)/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-05-01-preview"
    }

    # Empty Resource Group Details
    if ($Backup_ResourceGroupDetails -eq 1){
        $queries += "https://management.azure.com/subscriptions/$($subscription)/resourcegroups?api-version=2021-04-01"
    }


    # Role Assignments - probably the privilege required for a Service Account is unlikely for this to be used
    if ($Backup_RoleAssignments -eq 1){
        $queries += "https://management.azure.com/subscriptions/$($subscription)/providers/Microsoft.Authorization/roleAssignments?api-version=2017-05-01"
    }

    # Policy Set definitions
    if ($Backup_PolicySetDefinitions -eq 1){
        $queries += "https://management.azure.com/subscriptions/$($subscription)/providers/Microsoft.Authorization/policySetDefinitions?api-version=2021-06-01"
    }

    # Policy Definition
    if ($Backup_PolicyDefinitions -eq 1){
        $queries += "https://management.azure.com/subscriptions/$($subscription)/providers/Microsoft.Authorization/policyDefinitions?api-version=2021-06-01"
    }

    # Policy Assignments
    if ($Backup_PolicyAssignments -eq 1){
        $queries += "https://management.azure.com/subscriptions/$($subscription)/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01"
    }

    # Policy Exemptions
    if ($Backup_PolicyExemptions -eq 1){
        $queries += "https://management.azure.com/subscriptions/$($subscription)/providers/Microsoft.Authorization/policyExemptions?api-version=2022-07-01-preview"
    }

    # Security Center Subscriptions
    if ($Backup_SecurityCenteSubscriptions -eq 1){
        $queries += "https://management.azure.com/subscriptions/$($subscription)/providers/Microsoft.Security/pricings?api-version=2022-03-01"
    }

}



# Make sure the subscription objects collection is empty
$subscriptionobjects  =@()

foreach ($queryuri in $queries){

write-debug "+ QueryURI = $($queryuri)"
# Get the first set of returned objects into an array
# There are likely to be many pages worth - if so, the response will have a nextlink url
$response             = Invoke-RestMethod -Uri $queryuri -Method GET -Headers $authHeader -TimeoutSec 150
$subscriptionobjects += $response.value

    while($response.nextLink)
    {
        # Grab any additional pages of objects recursively until no more nextlink responses exist
        $nextLink = $response.nextLink


        $response = Invoke-RestMethod -Uri $nextLink -Method GET -Headers $authHeader -TimeoutSec 150
        $subscriptionobjects += $response.value
    }

}


# At this point $subscriptionobjects contains object references for each object in the subscription
# $subscriptionobjects


# Remove any old objects from the Backup folder
if ($BackupDir){

$null = Remove-Item $BackupDir$($slash)* -Recurse -Force

#Linux dir removal only valid for Github
<#
if($OS -eq 'win' ){ Remove-Item $BackupDir$($slash)* -Recurse -Force }
if($OS -eq 'linux' ){

#

$foldersToDel = Get-ChildItem $BackupDir -Directory
$foldersToDel

$ExcludeFolders=@(".git",".github")

foreach ($folder in $foldersToDel){

    if ($ExcludeFolders.Contains($folder.Name ) ){write-output "Folder Name in Exclude list = $($folder.Name)"}else{
      $folder | remove-item -force -Recurse
    }
}

}
#>
}

# Recurse through all subscription objects and retrieve content
# This needs a dictionary of all API versions to namespace types

# Get the API Versions dictionary for retrieving objects
# This lets us know what version needs to be used with a GET request.

Write-Debug "(Generate-Backup) calling - Get-Header -scope $scope  -Tenant $tenant -AppId $appid -secret $secret"
$authHeader = Get-Header -scope $scope  -Tenant $tenant -AppId $appid -secret $secret



# Azure Devops wont allow this function in a separate module
# security seems to strip out the authorization token from the header

function Get-AzureAPIVersions(){
param(
    [parameter( Mandatory = $true)]
    [hashtable]$Header,
    [parameter( Mandatory = $true)]
    [string]$SubscriptionID
)
<#
  Function:  Get-AzureAPIVersions

  Purpose:  Constructs a dictionary of current Azure namespaces

  Parameters:   -SubscriptionId      = The subscription ID of the environment to connect to.
                -Header              = A hashtable (header) with valid authentication for Azure Management

  Example:

             Get-AzureAPIVersions = Get-AnalyticsWorkspaceKey `
                                      -Header $header `
                                      -SubscriptionId "ed4ef888-5466-401c-b77a-6f9cd7cc6815"
#>
    $dict = @{}

    Try{
      $uri = "https://management.azure.com/subscriptions/$($SubscriptionID)/providers/?api-version=2015-01-01"

      Write-Debug "(Get-AzureAPIVersions calling - Invoke-RestMethod -Uri $uri"

      $result = Invoke-RestMethod -Uri $uri -Method GET -Headers $Header

      Write-Debug "(Get-AzureAPIVersions calling - Invoke-RestMethod -Uri $uri"
    $namespaces = $result.value

    foreach ($namespace in $namespaces){
       foreach ($resource in $namespace.resourceTypes){

       #Add Provider Plus Resource Type
        $dict.Add("$($namespace.namespace)/$($resource.resourceType)",$($resource.apiVersions | Get-latest) )
       }
     }

     #return dictionary
     $dict
    } catch {
      # catch any authentication or api errors
      Throw "Get-AzureAPIVersions failed - $($_.ErrorDetails.Message)"
    }

}







$AzAPIVersions = Get-AzureAPIVersions -header $authHeader -SubscriptionID $subscription




#write-debug $(convertto-json -inputobject $subscriptionobjects)

foreach ($azureobject in $subscriptionobjects ){


    $authHeader = Get-Header -scope $scope  -Tenant $tenant -AppId $appid -secret $secret


        try {
                $null = Invoke-azobjectbackup -Id $azureobject.id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
        }
        catch {
            Write-Warning "Object Backup failed for object with Id: $_"

        }

}

