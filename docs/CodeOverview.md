# Code Overview

The repository is completely written in PowerShell without use of compiled dependencies.  This provides you the ability to review and alter all code as you see fit.

The ability to backup a subscription to GitHub or Azure DevOps comes from the ability to derive the latest API versions for a given object type in Azure.  See this May 2020 blog post for more details: [Programmatically retrieving ‘latest’ Azure REST API versions | Laurie Rhodes. Info](https://www.laurierhodes.info/node/139).  All Azure objects can be retrieved with a REST GET action by using it's Id and the appropriate REST API version.

## generate-backup.yml

generate-backup.yml is the scheduled workflow responsible for orchestraing backup and report creation. For testing, this may be manually invoked although it will run on a schedule for production use.

### 1. Workflow Dispatch

The cron schedule for the backup is defined in this workflow.  Depending on where you are in the world, you will probably want to alter the time at which the scheduled backup occurs.

```text
  workflow_dispatch:
  schedule:
  # * is a special character in YAML so you have to quote this string
    - cron:  '30 17 * * *'
```

### 2. Environment Variables

The Backup workflow retrieves privileged information as GitHub secrets.  You must alter TENANT and SUBSCRIPTION environment variables to match the subscription you intend to backup.

```text
jobs:
  # This workflow contains a single job called "backup"
   backup:
    runs-on: ubuntu-latest
    env:
      TENANT: '<ENTER YOUR TENANT NAME>'
      SUBSCRIPTION: '<ENTER YOUR SUBSCRIPTION ID>'
      SCOPE: 'azure'
      DIRECTORY: '${{ github.workspace }}'
      CLOUDENV: 'AzureCloud'
      MAPPED_APP_ID: ${{ secrets.SUB_BACKUP_APP_ID }}
      MAPPED_APP_SECRET: ${{ secrets.SUB_BACKUP_APP_SECRET }} 
```

### 3. Exection Steps

Three PowerShell scripts are called from this workflow.

```text
      # Run PowerShell script to backup Azure
      - name: Backup Azure
        run: pwsh ./.github/workflows/generate-backup.ps1

      # Run PowerShell script to create audit reports
      - name: Creating Reports
        run: pwsh ./.github/workflows/generate-audit.ps1

      # Run PowerShell script to Generate Git History
      - name: Backup Azure
        run: pwsh ./.github/workflows/generate-githistory.ps1
```

The **main script** is the backup script.  Its role is to retrieve all the objects it can from your configured subscription and commit them to your repository as curated JSON object files.

The **audit reporting script** recursively calls a series of report scripts that create MarkDown reports from recursing the saved JSON files.

The **GitHistory script** creates a menu within Git that allows for previous dates to be reviewed within the repor.  This is largely redundant and may be removed in the future.



# generate-backup.ps1

The generate-backup script is long but very straightforward.  The 'main' element is at the end - starting around line 1100.

The script starts by creating a token with read access to a subscription.  This uses the credentials added as GitHub repository secrets.

```powershell
    $authHeader = Get-Header -scope $scope -Tenant $tenant -AppId $appid `
                             -secret $secret
```

At the very start of the backup script are defaults for different types of objects to backup, some of which require different permissions to be granted to the service account doing the backup.  By default only typical subscription objects are backed up to the repo.

```powershell
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
$Backup_SecurityCenterSubscriptions = 0
```

These default settings control the initial recursion of objects that will be retrieved for backup (about line 1143): e.e.

```powershell

    # Get all Subscription objects
    if ($Backup_SubscriptionObjects -eq 1){
        $queries += "https://management.azure.com/subscriptions/$($subscription)/resources?api-version=2021-04-01"
    }

    # Role Definitions
    if ($Backup_RoleDefinitions -eq 1){
        $queries += "https://management.azure.com/subscriptions/$($subscription)/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-05-01-preview"
    }

```

This will create a collection of subscriptionobjects, which is a list of Azure object IDs.

When this list of objects has been created, the function 'Invoke-AZObjectBackup' is recrsively called against each of them.



```powershell
foreach ($azureobject in $subscriptionobjects ){
    $authHeader = Get-Header -scope $scope  -Tenant $tenant -AppId $appid -secret $secret
        try {
                $null = Invoke-AZObjectBackup -Id $azureobject.id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
        }
        catch {
            Write-Warning "Object Backup failed for object with Id: $_"
        }
}

```

A bit of wrangling goes on to create a meaningful but short file name derived from the object for writing to GitHub.  Before it is written, the Azure object is run through the function '**Clean-AzureObject**'. 

### Clean-AzureObject

This function has grown with time and does require maintenance as new object types are added to Azure by Microsoft.

The intention was to remove read-only properties from Azure objects so I could simply deploy them again with REST.  Over the years I've added to this cleaning exercise...

```powershell
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
```

Occassionally you will find there are subordinate object types attached to "base" objects that you really want to back up.    In these circumstances I have added these extensions in with the clean script to recursively back up these elements too.

```powershell
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
                            $null = Invoke-AZObjectBackup -Id $element.id -BackupDir $BackupDir -AzAPIVersions $AzAPIVersions -authHeader $authHeader
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
```

When completed, the GitHub pipeline will preserve an entire copy of the targeted subscription in the JSON folder at the root of the repo.  This will allow recursive reports to be generated off the JSON as part of the scheduled action.
