# Code Overview

The repository is completely written in PowerShell without use of compiled dependencies.  This provides you the ability to review and alter all code as you see fit.

The ability to backup a subscription to GitHub or Azure DevOps comes from the ability to derive the latest API versions for a given object type in Azure.  See this May 2020 blog post for more details: "Programmatically retrieving ‘latest’ Azure REST API versions" [https://www.laurierhodes.info/node/139].  All Azure objects can be retrieved with a REST GET action by using it's Id and the appropriate REST API version.

## generate-backup.yml

generate-backup.yml is the scheduled workflow responsible for orchestraing backup and report creation. For testing, this may be manually invoked although it will run on a schedule for production use.

### 1. Workflow Dispatch

The cron schedule for the backup is defined in this workflow.  Depending on where you are in the world, you will probably want to alter the time at which the scheduled backup occurs.

``` text
  workflow_dispatch:
  schedule:
  # * is a special character in YAML so you have to quote this string
    - cron:  '30 17 * * *'
```


### 2. Environment Variables

The Backup workflow retrieves privileged information as GitHub secrets.  You must alter TENANT and SUBSCRIPTION environment variables to match the subscription you intend to backup.

``` text
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

``` text
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
The main script is the backup script.  Its role is to retrieve all the objects it can from your configured subscription and commit them to your repository as curated JSON object files.

The audit reporting script recursively calls a series of report scripts that create MarkDown reports from recursing the saved JSON files.

The GitHistory script creates a menu within Git that allows for previous dates to be reviewed within the repor.  This is largely redundant and may be removed in the future.

