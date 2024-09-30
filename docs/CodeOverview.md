# Code Overview

The repository is completely written in PowerShell without use of compiled dependencies.  This provides you the ability to review and alter all code as you see fit.

The ability to backup a subscription to GitHub or Azure DevOps comes from the ability to derive the latest API versions for a given object type in Azure.  See this May 2020 blog post for more details: "Programmatically retrieving ‘latest’ Azure REST API versions" [https://www.laurierhodes.info/node/139].  All Azure objects can be retrieved with a REST GET action by using it's Id and the appropriate REST API version.

## generate-backup.yml

generate-backup.yml is the scheduled workflow responsible for orchestraing backup and report creation. 


