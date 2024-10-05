[CmdletBinding()]
    param(
        [Parameter(mandatory=$false)]
        [string]$reportdir="D:\GitHub\PUBLIC-Subscription-Backup\reports",
        [Parameter(mandatory=$false)]
        [string]$backupdir="D:\GitHub\PUBLIC-Subscription-Backup\json",
        [Parameter(mandatory=$false)]
        [string]$moduledir="D:\GitHub\PUBLIC-Subscription-Backup\.github\workflows\modules",
        [Parameter(mandatory=$false)]
        [psobject]$Filelist

    )


<#

Purpose is to generate .md files for the report Index

#>
#$DebugPreference = 'Continue'



if ((Get-ChildItem Env:PATH).Value -Match '/'){ $OS='linux'}else{$OS='win'}
if($OS -eq 'win' ) { $slash = "\" }
if($OS -eq 'linux'){ $slash = "/"}

# "deviceManagement\deviceConfigurations"
$files = Get-ChildItem "$($reportdir)" -Filter "README.md" -Recurse -Depth 1

# If a filelist hasn't been passed - create one
if ( !($Filelist) ){$Filelist =  Get-ChildItem $backupdir -Filter "*.json" -Recurse }


#The output of the Index will be the root folder
$outputpath = "$($reportdir)"

# Make sure the output directory exists
New-Item -ItemType Directory -Force -Path $outputpath

# Create a Report object class to contain all the harvested fields that interest me.
# this will allow results to be sorted before being written to file

Class oResult{
    [String]$ReportName
    [String]$Path
    [String]$IsModified
}

# Init Output Array
$OutputArray =@()





 # Populate the content

# Recurse through all objects
for ($i=0; $i -lt $files.Count; $i++) {

    # Get the first line of each README file
     $otemplate = Get-Content -Path $files[$i].FullName


     $otemp = New-Object oResult

     # First heading line of each MD file is the title of the report
     $Reportname = $otemplate -match "# "
     $Reportname = $Reportname.Replace('#','')
     $Reportname = $Reportname.Trim()
     $otemp.ReportName = $Reportname.Replace('x','')

     # Path variable needs to be a relative path
     $relativepath = ($files[$i].FullName).Substring( $reportdir.Length +1 ,(($files[$i].FullName).Length - ($reportdir.Length +1)))
     $otemp.Path = $relativepath

     #  // TODO Git diff
     # $otemp.IsModified

     # Don't create a circular link to the root report
     if ($otemp.Path -ne "README.md"){
        $OutputArray += $otemp
      }

}

#  Sort the output

$OutputArray  = $OutputArray  | sort-object  -Property ReportName



# Create the MD Header

$header =@"
![](img$($slash)header.jpg)

# Reports




| Report                      | Path                |Is Modified |
| --------------------------- | ------------------- |----------- |
"@

 $null = out-file -FilePath "$($outputpath)$($slash)README.md"  -Force -InputObject $header


$OutputArray | ForEach-Object {


  "| $($_.ReportName)     | [$($_.Path)]($($_.Path))        | $($_.IsModified )         |" | out-file -FilePath "$($outputpath)$($slash)README.md"  -Append

}


$footer = @"

![logo](img$($slash)logo.jpg)
"@

 $null = out-file -FilePath "$($outputpath)$($slash)README.md"  -Append -InputObject $footer