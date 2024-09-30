# Azure Subscription Backup

## Overview

This repository contains an export of Azure objects from the Security subscription.  This export is configured to run daily and produces Markdown reports to view the content of Security services that may be used for reference of previous state or redeployment in times of critical need. 

Microsoft Sentinel is a Portal tool that allows Security Operations staff to easily create detections on the basis of ad-hoc queries being made.  Many organisations have tried to force staff to manage Sentinel through CI/CD pipelines, ignoring the necessity of staff members to use the portal as a security tool.

This project provides an ability to preserve a daily backup of Microsoft Sentinel.

Subscription objects are retrieved and stored as JSON and "cleaned" to remove read-only properties that prevent a redeployment.  Audit reporting runs as part of the GitHub pipeline that produces Markdown representations of detections. saved queries, workbooks etc.  These Markdown files can be used with Github to see previous versions of KQL and dates of changes if required.

## Table of Contents

- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Setup Instructions](#setup-instructions)
  - [1. Clone the Repository](#1-clone-the-repository)
  - [2. Configure Azure Credentials](#2-configure-azure-credentials)
- [Usage](#usage)
- [License](#license)

## Project Structure

```plaintext
Subscription-Backup/
+-- .github/
  +-- .workflows/
    +-- audit-resources/
      +-- 000_Settings.ps1
      +-- 001_Workbooks.ps1
      +-- 002_SourceControls.ps1
      +-- 003_scheduledqueryrules.ps1
      +-- 004_connections.ps1
      +-- 005_alertRules.ps1
      +-- 006_ActivityLogAlerts.ps1
      +-- 007_entityQueries.ps1
      +-- 009_Playbooks.ps1
      +-- 010_savedSearches.ps1
      +-- 999_Index.ps1
    +-- git-history/
      +-- 000_60-Days.ps1
      +-- 001_Commits.ps1
      +-- 999_Index.ps1
    +-- modules/
      +-- AZRest/
        +-- AZRest.psd1
        +-- AZRest.psm1
  +-- generate-audit.ps1   
  +-- generate-audit.yml    
  +-- generate-backup.ps1  
  +-- generate-backup.yml  
  +-- generate-githistory.ps1
  +-- generate-githistory.yml
+-- docs/      
+-- githistory/ 
+-- json/
+-- reports/
```

## Prerequisites

- Azure Subscription
- GitHub repository with the following secrets:

- `AZURE_SUBSCRIPTION`: Your Azure Subscription ID
- `SUB_BACKUP_APP_ID`: The Client ID of your Azure AD app registration
- `SUB_BACKUP_APP_SECRET`: The Client Secret of your Azure AD app registration
- `AZURE_TENANT_ID`: Your Azure AD Tenant ID

## Setup Instructions

### 1. Clone the Repository

```sh
git clone https://github.com/LaurieRhodes/PUBLIC-Subscription-Backup.git
cd PUBLIC-Subscription-Backup
```

### 2. Create App Registration

This project requires that an App Registration / Service Principal be created and privided Reader permissions to the subscription being backed up.  The App ID and Secret must be added to this GithHub project as secrets in the next step.

### 3. Set Up GitHub Secrets

Add the following secrets to your GitHub repository.  

SUB_BACKUP_APP_ID
SUB_BACKUP_APP_SECRET

REPOTOKEN ****

Optionally, a Github token with repo scope may be added to allow commits to be viewed as a menu within the project.  Although interesting, this capability is part of Github natively and is redundant.


### 4. Customise /.github/workflows/generate-backup.yml

Modify the generate backup workflow to include your Tenant name and subscription ID.
``` text
    env:
      TENANT: '<ENTER YOUR TENANT NAME>'
      SUBSCRIPTION: '<ENTER YOUR SUBSCRIPTION ID>'
```

### 4. Customise /.github/workflows/generate-githistory.yml

Modify the generate githistory workflow to include your Tenant name and subscription ID.
``` text
    env:
      TENANT: '<ENTER YOUR TENANT NAME>'
      SUBSCRIPTION: '<ENTER YOUR SUBSCRIPTION ID>'
```

## Usage

Once deployed, the backup pipeline will run daily.

Review daily reports by following the links from the root README,md

[Code Overview](./CodeOverview.md)

[Audit Reports](./AuditReports.md)

## License

This project is licensed under the MIT License. See the LICENSE file for details.
