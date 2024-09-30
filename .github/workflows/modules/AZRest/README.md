# AZRest

Powershell Module for authenticating and working with Azure (and other Microsoft cloud) services using REST (no dll dependency).

Not using developer kit modules or powershell cmdlets removes the prospect of "dll hell" or issues with conflicting cmdlets.  I've found that managing Azure with REST is much easier and more reliable than using cmdlets.

## Download And Import

Either, download all the files into your PowerShell module path (usually C:\Program Files\WindowsPowerShell\Modules) and import it...

```powershell
Import-Module -Name 'AZRest'
```

or, download or clone the module files and dynamically import the module from that file location:

```powershell
 Import-Module "C:\Users\Laurie\Documents\GitHub\AZRest\AZRest.psm1" 
```

Tip: If you don't have an unzip utility like 7-Zip installed, using the native Microsoft 'extract' for zip files will mark all scripts as "blocked".  You'll need to clear the blocked tag.  This can be done with PowerShell.

```powershell
Get-ChildItem -Path "C:\Users\laurie\Downloads\AZRest-main\" -Recurse | unblock-file -confirm
```

### Code Example - Retrieving a single object from Azure

An object can be seen in Azure in its JSON format but this example shows how to programatically retrieve the same representation of the object.

```powershell
Import-Module "C:\<my module install path>\AZRest.psm1"

$Tenant         = "mytenant.onmicrosoft.com" #Used for authenticating
$subscriptionID = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' # needed to retreive the current list of API versions
$outfolder      = 'c:\temp" # where to export my Azure objects to. 

# Specify an object Id to retrieve

$id = '/subscriptions/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/resourceGroups/xxxxxxxxxxxxxxxx/providers/Microsoft.Insights/dataCollectionRules/my-datacollection-rule'


# As an example - use an inteactive authentication rather than the various Service Account options

$authheader = Get-Header -interactive -Tenant $Tenant  -Scope azure 

# Retrieve an up to date list of namespace versions (once per session)
# All REST API functions need an appended version ID in Azure.
# We create a dictionary and reference it with functions.

if (!$AzAPIVersions){$AzAPIVersions = Get-AzureAPIVersions -header $authHeader -SubscriptionID $subscriptionID}


$object = $null

# Get  a PowerShell object for the Azure object specified
$object =  Get-Azureobject -AuthHeader $authHeader -apiversions $AzAPIVersions -id $id

Out-File -FilePath "$($outfolder)\$($object.name).json" -InputObject (convertto-json -InputObject $object -Depth 10) -Force 
```
