[CmdletBinding()]
    param(
        #[Parameter(mandatory=$false)]
        #[string]$reportdir="C:\Users\Laurie\Documents\GitHub\Sentinel-as-Code\reports",
        #[Parameter(mandatory=$false)]
        #[string]$backupdir="C:\Users\Laurie\Documents\GitHub\Sentinel-as-Code\json",
        #[Parameter(mandatory=$false)]
        #[string]$githistorydir="C:\Users\Laurie\Documents\GitHub\Sentinel-as-Code\githistory",
        #[Parameter(mandatory=$false)]
        #[string]$moduledir="C:\Users\Laurie\Documents\GitHub\Sentinel-as-Code\.github\workflows\modules",
        [Parameter(mandatory=$true)]
        [string]$githistorydir,
        [Parameter(mandatory=$true)]
        [string]$reportdir,
        [Parameter(mandatory=$true)]
        [string]$backupdir,
        [Parameter(mandatory=$true)]
        [string]$moduledir
    )


<#

Purpose is to create a menu list og previous git HEAD archives

#>
#$DebugPreference = 'Continue'

$FriendlyName = "Repo Backup"

if ((Get-ChildItem Env:PATH).Value -Match '/'){ $OS='linux'}else{$OS='win'}

if($OS -eq 'win' ) { $slash = "\" }
if($OS -eq 'linux'){ $slash = "/"}

Import-Module "$($moduledir)$($slash)AZRest$($slash)AZRest.psm1" | write-debug


$outputpath = "$($githistorydir)$($slash)60-Day-Git-History"


write-debug "Establishing Output Path $($outputpath)"



# Make sure old reports don't exist
if (Test-Path $outputpath) {
  Remove-Item $outputpath -Recurse -Force
}

# Make sure the output directory exists
 $null = New-Item -ItemType Directory -Force -Path $outputpath



# Create a Report object class to contain all the harvested fields that interest me.
# This will be unique with each report
# this will allow results to be sorted before being written to file

Class oResult{
    [String]$Date
    [String]$Day
    [String]$View
}



# Init Output Array
$OutputArray =@()

$i =0

Do {
    $i
    $targetdate = (Get-Date).AddDays(-$i)
    "$($targetdate.DayOfWeek)  $($targetdate.Day) $((Get-Culture).DateTimeFormat.GetMonthName($targetdate.Month)) $($targetdate.Year)"


     $otemp = New-Object oResult
     $otemp.Date = "$($targetdate.Day) $((Get-Culture).DateTimeFormat.GetMonthName($targetdate.Month)) $($targetdate.Year)"
     $otemp.Day  = $($targetdate.DayOfWeek)
     if ($env:GITHUB_SERVER_URL){
        $otemp.View = "[view repo]($($env:GITHUB_SERVER_URL)/$($env:GITHUB_REPOSITORY)/tree/HEAD@%7B$($targetdate.Year)-$($targetdate.Month)-$($targetdate.Day)%7D)"
      }else{
        $otemp.View = "[view repo](https://github.com/$($env:GITHUB_REPOSITORY)/tree/HEAD@%7B$($targetdate.Year)-$($targetdate.Month)-$($targetdate.Day)%7D)"
      }

     $OutputArray += $otemp


    $i++
    }
While ($i -le 60)




# Sort the output
#$OutputArray  = $OutputArray  | sort-object  -Property Name



# Create the MD Header

$header =@"
![](..$($slash)..$($slash)reports$($slash)img$($slash)header.jpg)

# $($FriendlyName)

View an archive of the repository as a point in time from the previous 60 days


| Name                 | Day         |View Archive              |
| -------------------- |-------------|-------------------------|
"@

 $null = out-file -FilePath "$($outputpath)$($slash)README.md"  -Force -InputObject $header


$OutputArray | ForEach-Object {

  "| $($_.date)    | $($_.day)    | $($_.view)    |" | out-file -FilePath "$($outputpath)$($slash)README.md"  -Append
}

$footer = @"

![](..$($slash)..$($slash)reports$($slash)img$($slash)logo.jpg)
"@

 $null = out-file -FilePath "$($outputpath)$($slash)README.md"  -Append -InputObject $footer






