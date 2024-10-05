<#

Module Name:

    AZRest.psm1

Description:

    Provides Azure Rest API

Version History

    1.0    - 7 July 2020    Laurie Rhodes       Initial Release

#>



function Get-Header(){
<#
  Function:  Get-Header

  Purpose:  To Generically produce a header for use in calling Microsoft API endpoints

  Parameters:   -Username   = Username
                -Password   = password

                -AppId      = The AppId of the App used for authentication
                -Thumbprint = eg. B35E2C978F83B49C36116802DC08B7DF7B58AB08

                -Tenant     = disney.onmicrosoft.com

                -Scope      = "analytics"- data plane of log analytics
                                            "https://api.loganalytics.io/v1/workspaces"

                              "azure"    - Azure Resource Manager
                                           "https://management.azure.com/"

                              "exchange"  - Microsoft Exchange Online
                                           "https://outlook.office365.com/"

                              "graph"    - Microsoft Office and Mobile Device Management (Graph)
                                            "https://graph.microsoft.com/beta/groups/'

                              "keyvault" - data plane of Azure keyvaults
                                            "https://<keyvaultname>.vault.azure.net/certificates/"

                              "o365"      - Office 365 admin portal
                                            "https://admin.microsoft.com/"

                              "portal"   - api interface of the Azure portal (only supports username / password authentication)
                                            "https://main.iam.ad.ext.azure.com/api/"

                              "sharepoint" - Sharepoint
                                            "https://<Tenant>-admin.sharepoint.com"

                              "storage"  - data plane of Azure storage Accounts (table)
                                            "https://<storageaccount>.table.core.windows.net/"

                              "teams"     - Teams admin Portal
                                            https://api.interfaces.records.teams.microsoft.com//"

                              "windows"  - api interface of legacy Azure AD  (only supports username / password authentication)
                                            "https://graph.windows.net/<tenant>/policies?api-version=1.6-internal"


                -Proxy      = "http://proxy:8080" (if operating from behind a proxy)

                -ProxyCredential = (Credential Object)

                -Interactive  = suitable for use with MFA enabled accounts

  Example:

     Get-Header -scope "portal" -Tenant "disney.com" -Username "Donald@disney.com" -Password "Mickey01"
     Get-Header -scope "graph" -Tenant "disney.com" -AppId "aa73b052-6cea-4f17-b54b-6a536be5c832" -Thumbprint "B35E2C978F83B49C36611802DC08B7DF7B58AB08"
     Get-Header -scope "azure" -Tenant "disney.com" -AppId "aa73b052-6cea-4f17-b54b-6a536be5c715" -Secret 'xznhW@w/.Yz14[vC0XbNzDFwiRRxUtZ3'
     Get-Header -scope "azure" -Tenant "disney.com" -Interactive


#>
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName="User")]
        [string]$Username,
        [Parameter(ParameterSetName="User")]
        [String]$Password,
        [Parameter(ParameterSetName="App")]
        [Parameter(ParameterSetName="App2")]
        [string]$AppId,
        [Parameter(ParameterSetName="App")]
        [string]$Thumbprint,
        [Parameter(mandatory=$true)]
        [string]$Tenant,
        [Parameter(mandatory=$true)]
        [ValidateSet(
            "analytics",
            "azure",
            "exchange",
            "graph",
            "keyvault",
            "o365",
            "portal",
            "sharepoint",
            "storage",
            "windows",
            "teams"
        )][string]$Scope,
        [Parameter(ParameterSetName="App2")]
        [string]$Secret,
        [Parameter(ParameterSetName="inter")]
        [Switch]$interactive=$false,
        [Parameter(mandatory=$false)]
        [string]$Proxy,
        [Parameter(mandatory=$false)]
        [PSCredential]$ProxyCredential
    )


    begin {


       $ClientId       = "1950a258-227b-4e31-a9cf-717495945fc2"


       switch($Scope){
           'portal' {$TokenEndpoint = "https://login.microsoftonline.com/$($tenant)/oauth2/token"
                    $RequestScope = "https://graph.microsoft.com/.default"
                    $ResourceID  = "74658136-14ec-4630-ad9b-26e160ff0fc6"
                    }
           'azure' {$TokenEndpoint = "https://login.microsoftonline.com/$($tenant)/oauth2/v2.0/token"
                    $RequestScope = "https://management.azure.com/.default"
                    $ResourceID  = "https://management.azure.com/"
                    }
           'graph' {$TokenEndpoint = "https://login.microsoftonline.com/$($tenant)/oauth2/token"
                    $RequestScope = "https://graph.microsoft.com/.default"
                    $ResourceID  = "https://graph.microsoft.com"
                    }
           'keyvault'{$TokenEndpoint = "https://login.microsoftonline.com/$($tenant)/oauth2/v2.0/token"
                    $RequestScope = "https://vault.azure.net/.default"
                    $ResourceID  = "https://vault.azure.net"
                    }
           'storage'{$TokenEndpoint = "https://login.microsoftonline.com/$($tenant)/oauth2/v2.0/token"
                    $RequestScope = "https://storage.azure.com/.default"
                    $ResourceID  = "https://storage.azure.com/"
                    }
           'analytics'{$TokenEndpoint = "https://login.microsoftonline.com/$($tenant)/oauth2/v2.0/token"
                    $RequestScope = "https://api.loganalytics.io/.default"
                    $ResourceID  = "https://api.loganalytics.io/"
                    }
           'windows'{$TokenEndpoint = "https://login.microsoftonline.com/$($tenant)/oauth2/token"
                    $RequestScope = "openid"
                    $ResourceID  = "https://graph.windows.net/"
                    }
           'teams'{$TokenEndpoint = "https://login.microsoftonline.com/$($tenant)/oauth2/v2.0/token"
                    $RequestScope = "https://api.interfaces.records.teams.microsoft.com/user_impersonation"
                    $ResourceID  = "https://api.interfaces.records.teams.microsoft.com/"
                    }
           'O365'{$TokenEndpoint = "https://login.microsoftonline.com/$($tenant)/oauth2/v2.0/token"
                    $RequestScope = 'https://admin.microsoft.com/.default'
                    $ResourceID  =  'https://admin.microsoft.com'
                    }
           'Exchange'{$TokenEndpoint = "https://login.microsoftonline.com/$($tenant)/oauth2/v2.0/token"
                    $RequestScope = 'https://outlook.office365.com/.default'
                    $ResourceID  =  'https://outlook.office365.com'
                    }
           'Sharepoint'{$TokenEndpoint = "https://login.microsoftonline.com/common/oauth2/token"
                    $RequestScope = "https://$($Tenantshortname)-admin.sharepoint.com/.default"
                    $ResourceID  =  "https://$($Tenantshortname)-admin.sharepoint.com"
                    }
           default { throw "Scope $($Scope) undefined - use azure or graph'" }
        }


        #Set Accountname based on Username or AppId
        if (!([string]::IsNullOrEmpty($Username))){$Accountname = $Username }
        if (!([string]::IsNullOrEmpty($AppId))){$Accountname = $AppId }



    }

    process {
        #Credit to https://adamtheautomator.com/powershell-graph-api/#Acquire_an_Access_Token_Using_a_Certificate
        # Authenticating with Certificate
        if (!([string]::IsNullOrEmpty($Thumbprint)) -And ($interactive -eq $false)){
            write-debug "+++ Certificate Authentication"

            # Try Local Machine Certs
            $Certificate = ((Get-ChildItem -Path Cert:\LocalMachine  -force -Recurse )| Where-Object {$_.Thumbprint -match $Thumbprint});
            if ([string]::IsNullOrEmpty($Certificate)){
            # Try Current User Certs
            $Certificate = ((Get-ChildItem -Path Cert:\CurrentUser  -force -Recurse )| Where-Object {$_.Thumbprint -match $Thumbprint});
            }

            if ([string]::IsNullOrEmpty($Certificate)){throw "certificate not found"}


            # Create base64 hash of certificate
            $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())

            # Create JWT timestamp for expiration
            $StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
            $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
            $JWTExpiration = [math]::Round($JWTExpirationTimeSpan,0)

            # Create JWT validity start timestamp
            $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
            $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan,0)

            # Create JWT header
            $JWTHeader = @{
                alg = "RS256"
                typ = "JWT"
                x5t = $CertificateBase64Hash -replace '\+','-' -replace '/','_' -replace '='
            }

            # Create JWT payload
            $JWTPayLoad = @{
                aud = $TokenEndpoint
                exp = $JWTExpiration
                iss = $AppId
                jti = [guid]::NewGuid()
                nbf = $NotBefore
                sub = $AppId
            }


            # Convert header and payload to base64
            $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))
            $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)

            $JWTPayLoadToByte =  [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))
            $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)

            # Join header and Payload with "." to create a valid (unsigned) JWT
            $JWT = $EncodedHeader + "." + $EncodedPayload

            # Get the private key object of your certificate
            $PrivateKey = $Certificate.PrivateKey
            if ([string]::IsNullOrEmpty($PrivateKey)){throw "Unable to access certificate Private Key"}

            # Define RSA signature and hashing algorithm
            $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
            $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

            # Create a signature of the JWT

            $Signature = [Convert]::ToBase64String( $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT),$HashAlgorithm,$RSAPadding) ) -replace '\+','-' -replace '/','_' -replace '='

            $JWTBytes = [System.Text.Encoding]::UTF8.GetBytes($JWT)


            # Join the signature to the JWT with "."
            $JWT = $JWT + "." + $Signature

       # Construct the initial JSON Body request
       $Body = @{}

       $Body.Add('client_id', $AppId )  # used with all
       $Body.Add('client_assertion', $JWT)  # used with all
       $Body.Add('client_assertion_type', "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")  # used with all scopes
       $Body.Add('scope', $RequestScope)
       $Body.Add('grant_type', 'client_credentials')

       switch($Scope){
           'analytics' {}
           'azure' {}
           'graph' {
                      $Body.Add('username', $Accountname)
                    }
           'exchange' {}
           'keyvault' {}
           'sharepoint' {}
           'storage' {}
           'teams' {}
           'O365' {}
           'portal' {
                        throw "FATAL Error - portal requests only support username and password (non interactive) flows"
                    }
           'windows' {
                        throw "FATAL Error - legacty windows graph requests only support username and password (non interactive) flows"
                    }
        }# end switch


            $Url = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token"

            # Use the self-generated JWT as Authorization
            $Header = @{
                Authorization = "Bearer $JWT"
            }

            # Splat the parameters for Invoke-Restmethod for cleaner code
            $PostSplat = @{
                ContentType = 'application/x-www-form-urlencoded'
                Method = 'POST'
                Body = $Body
                Uri = $Url
                Headers = $Header
            }


            #Get Bearer Token
            $Request = Invoke-RestMethod @PostSplat
            # Create header
            $Header = $null
            $Header = @{
                Authorization = "$($Request.token_type) $($Request.access_token)"
            }


        } # End Certificate Authentication



        # Authenticating with Password
        if (!([string]::IsNullOrEmpty($Password)) -And ($interactive -eq $false)){


        # Construct the initial JSON Body request
       $Body = @{}

       $Body.Add('username', $Accountname )
       $Body.Add('password', $Password)
       $Body.Add('client_id', $clientId)
       $Body.Add('grant_type', 'password')



       switch($Scope){
           'portal' {
                        $Body['clientid'] = '1950a258-227b-4e31-a9cf-717495945fc2'
                        $Body.Add('resource', '74658136-14ec-4630-ad9b-26e160ff0fc6')
            }
           'analytics' {
                        $Body.Add('scope', $RequestScope)
            }
           'azure' {
                        $Body.Add('resource', $RequestScope)
           }

           'graph' {
                        $Body.Add('username', [system.uri]::EscapeDataString($ResourceID))
                    }
           'exchange' {
                         $Body.Add('scope', $RequestScope)
           }
           'keyvault' {
                         $Body.Add('scope', $RequestScope)
           }
           'sharepoint' {
                         $Body.Add('scope', $RequestScope)
           }
           'storage' {
                         $Body.Add('scope', $RequestScope)
           }
           'teams' {
                         $Body.Add('scope', $RequestScope)
           }
           'O365' {
                         $Body.Add('scope', $RequestScope)
           }
           'windows' {
                         $Body.Add('resource', [system.uri]::EscapeDataString($ResourceID))
                    }
        }# end switch

        } # end password block



        # Authenticating with Secret
        if (!([string]::IsNullOrEmpty($Secret)) -And ($interactive -eq $false)){

       # Construct the initial JSON Body request
       $Body = @{}

       $Body.Add('client_id', $AppId)
       $Body.Add('client_secret', $Secret)
       $Body.Add('grant_type', 'client_credentials')
       $Body.Add('scope', $RequestScope)

       switch($Scope){
           'analytics' {}
           'azure' {}
           'graph' {
                      $Body.Remove('scope')
                      $Body.Add('resource', [system.uri]::EscapeDataString($ResourceID))
                    }
           'exchange' {}
           'keyvault' {}
           'sharepoint' {}
           'storage' {}
           'teams' {}
           'O365' {}
           'portal'{
                        throw 'FATAL Error - portal requests only support username and password (non interactive) flows'
                    }
           'windows' {}
        }# end switch

       } # end secret block



        # Interfactive Authentication
         if($interactive -eq $true){


            # Load Web assembly when needed
            # PowerShell Core has the assembly preloaded
            if (!("System.Web.HttpUtility" -as [Type])) {
                Add-Type -Assembly System.Web
            }

             $response_type         = "code"
             $redirectUri           = [System.Web.HttpUtility]::UrlEncode("http://localhost:8400/")
             $redirectUri           = "http://localhost:8400/"
             $code_challenge_method = "S256"
             $state                 = "141f0ce8-352d-483a-866a-79672b952f8e668bc603-ea1a-43e7-a203-af3abe51e2ea"
             $resource = [System.Web.HttpUtility]::UrlEncode("https://graph.microsoft.com")
             $RandomNumberGenerator = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
             $Bytes = New-Object Byte[] 32
             $RandomNumberGenerator.GetBytes($Bytes)
             $code_verifier = ([System.Web.HttpServerUtility]::UrlTokenEncode($Bytes)).Substring(0, 43)
             $code_challenge = ConvertFrom-CodeVerifier -Method s256 -codeVerifier $code_verifier


             $url = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?scope=$($RequestScope)&response_type=$($response_type)&client_id=$($clientid)&redirect_uri=$([System.Web.HttpUtility]::UrlEncode($redirectUri))&prompt=select_account&code_challenge=$($code_challenge)&code_challenge_method=$($code_challenge_method)"

             # portal requests only support username and password (non interactive) flows
            if ($Scope -eq "portal"){

                throw "FATAL Error - portal requests only support username and password (non interactive) flows"

            }
             # portal requests only support username and password (non interactive) flows
            if ($Scope -eq "windows"){

                throw "FATAL Error - legacty windows graph requests only support username and password (non interactive) flows"

            }

            # Load Forms when needed
            if (!("System.Windows.Forms" -as [Type])) {
                Add-Type -AssemblyName System.Windows.Forms
            }

                $form = New-Object -TypeName System.Windows.Forms.Form -Property @{Width=440;Height=640}
                $web  = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{Width=420;Height=600;Url=($url -f ($RequestScope -join "%20")) }

                $DocComp  = {
                    $Global:uri = $web.Url.AbsoluteUri
                    if ($Global:uri -match "error=[^&]*|code=[^&]*") {$form.Close() }
                }
                $web.ScriptErrorsSuppressed = $true
                $web.Add_DocumentCompleted($DocComp)
                $form.Controls.Add($web)
                $form.Add_Shown({$form.Activate()})
                $form.ShowDialog() | Out-Null

                $queryOutput = [System.Web.HttpUtility]::ParseQueryString($web.Url.Query)
                $output = @{}
                foreach($key in $queryOutput.Keys){
                    $output["$key"] = $queryOutput[$key]
                }

                $authCode=$output["code"]



            # Get Access Token

             $Body = @{
                  client_id = $clientId
                  code = $authCode
                  code_verifier = $code_verifier
                  redirect_uri = $redirectUri
                  grant_type = "authorization_code"
              }



         } # end interactive block


            $RequestSplat = @{
                Uri = $TokenEndpoint
                Method = “POST”
                Body = $Body
                UseBasicParsing = $true
            }


           #Construct parameters if they exist
           if($Proxy){ $RequestSplat.Add('Proxy', $Proxy) }
           if($ProxyCredential){ $RequestSplat.Add('ProxyCredential', $ProxyCredential) }

           $Response = Invoke-WebRequest @RequestSplat
           $ResponseJSON = $Response|ConvertFrom-Json


            #Add the token to headers for the request
            $Header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $Header.Add("Authorization", "Bearer "+$ResponseJSON.access_token)
            $Header.Add("Content-Type", "application/json")

            # storage requests require two different keys in the header
            if ($Scope -eq "storage"){
                $Header.Add("x-ms-version", "2019-12-12")
                $Header.Add("x-ms-date", [System.DateTime]::UtcNow.ToString("R"))
            }

            # portal requests require two different keys in the header
            if ($Scope -eq "portal"){
                $Header.Add("x-ms-client-request-id", "$((New-Guid).Guid)")
                $Header.Add("x-ms-session-id", "12345678910111213141516")
            }

    }

    end {

       return $Header

    }

}







<#
  Function:  ConvertFrom-CodeVerifier

  Purpose:  Determines code-challenge from code-verifier for Azure Authentication

  Example:

           ConvertFrom-CodeVerifier -Method s256 -codeVerifier XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

  Author  https://gist.github.com/watahani
#>
function ConvertFrom-CodeVerifier {

    [OutputType([String])]
    param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [String]$codeVerifier,
        [ValidateSet(
            "plain",
            "s256"
        )]$Method = "s256"
    )
    process {
        switch($Method){
            "plain" {
                return $codeVerifier
            }
            "s256" {
                # https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-7
                $stringAsStream = [System.IO.MemoryStream]::new()
                $writer = [System.IO.StreamWriter]::new($stringAsStream)
                $writer.write($codeVerifier)
                $writer.Flush()
                $stringAsStream.Position = 0
                $hash = Get-FileHash -InputStream $stringAsStream | Select-Object Hash
                $hex = $hash.Hash
        
                $bytes = [byte[]]::new($hex.Length / 2)

                For($i=0; $i -lt $hex.Length; $i+=2){
                    $bytes[$i/2] = [convert]::ToByte($hex.Substring($i, 2), 16)
                }
                $b64enc = [Convert]::ToBase64String($bytes)
                $b64url = $b64enc.TrimEnd('=').Replace('+', '-').Replace('/', '_')
                return $b64url
            }
            default {
                throw "not supported method: $Method"
            }
        }
    }
}



function Get-Token(){
<#
  Function:  Get-Token

  Purpose:  To Generically produce a token for use in calling Microsoft API endpoints

            This is an Interactive Flow for use with Refresh tokens.  For Legacy authentication that doesnt use a refresh token
            use the Get-Header function

  Parameters:
                -Tenant     = disney.onmicrosoft.com
                -Scope      = graph / azure

                -Proxy      ="http://proxy:8080"
                -ProxyCredential = (Credential Object)

  Example:

     Get-Token -scope "azure" -Tenant "disney.com" -Interactive

#>
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName="App")]
        [string]$Thumbprint,
        [Parameter(mandatory=$false)]
        [string]$Tenant,
        [Parameter(mandatory=$true)]
        [ValidateSet(
            "azure",
            "graph",
            "keyvault",
            "storage",
            "analytics"
        )][string]$Scope,
        [Parameter(mandatory=$false)]
        [string]$Proxy,
        [Parameter(mandatory=$false)]
        [PSCredential]$ProxyCredential
    )



    begin {




       $ClientId       = "1950a258-227b-4e31-a9cf-717495945fc2"


       switch($Scope){
           'azure' {$TokenEndpoint = "https://login.microsoftonline.com/$($tenant)/oauth2/v2.0/token"
                    $RequestScope = "https://management.azure.com/.default"
                    $ResourceID  = "https://management.azure.com/"
                    }
           'graph' {$TokenEndpoint = "https://login.microsoftonline.com/$($tenant)/oauth2/token"
                    $RequestScope = "https://graph.microsoft.com/.default"
                    $ResourceID  = "https://graph.microsoft.com"
                    }
           'keyvault'{$TokenEndpoint = "https://login.microsoftonline.com/$($tenant)/oauth2/v2.0/token"
                    $RequestScope = "https://vault.azure.net/.default"
                    $ResourceID  = "https://vault.azure.net"
                    }
           'storage'{$TokenEndpoint = "https://login.microsoftonline.com/$($tenant)/oauth2/v2.0/token"
                    $RequestScope = "https://storage.azure.com/.default"
                    $ResourceID  = "https://storage.azure.com/"
                    }
           'analytics'{$TokenEndpoint = "https://login.microsoftonline.com/$($tenant)/oauth2/v2.0/token"
                    $RequestScope = "https://api.loganalytics.io/.default"
                    $ResourceID  = "https://api.loganalytics.io/"
                    }
           default { throw "Scope $($Scope) undefined - use azure or graph'" }
        }

        #Set Accountname based on Username or AppId
        if (!([string]::IsNullOrEmpty($Username))){$Accountname = $Username }
        if (!([string]::IsNullOrEmpty($AppId))){$Accountname = $AppId }


         $TokenObject = [PSCustomObject]@{
            token_type     = 'Bearer'
            token_endpoint = $TokenEndpoint
            scope          = $RequestScope
            access_token   = ''
            refresh_token  = ''
            client_id      = $clientId
            client_assertion = ''
            client_assertion_type = ''
            code           = ''
            code_verifier  = ''
            redirect_uri   = ''
            grant_type     = ''
            expires_in     = ''
        }
    }

    process {

        # Interfactive Authentication

            $TokenObject.grant_type = "authorization_code"

             $response_type         = "code"
             $redirectUri           = [System.Web.HttpUtility]::UrlEncode("http://localhost:8400/")
             $redirectUri           = "http://localhost:8400/"
             $code_challenge_method = "S256"
             $state                 = "141f0ce8-352d-483a-866a-79672b952f8e668bc603-ea1a-43e7-a203-af3abe51e2ea"
             #$resource = [System.Web.HttpUtility]::UrlEncode("https://graph.microsoft.com")
             $RandomNumberGenerator = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
             $Bytes = New-Object Byte[] 32
             $RandomNumberGenerator.GetBytes($Bytes)
             $code_verifier = ([System.Web.HttpServerUtility]::UrlTokenEncode($Bytes)).Substring(0, 43)

             $code_challenge = ConvertFrom-CodeVerifier -Method s256 -codeVerifier $code_verifier

             $url = "https://login.microsoftonline.com/$($tenant)/oauth2/v2.0/authorize?scope=$($RequestScope)&response_type=$($response_type)&client_id=$($clientid)&redirect_uri=$([System.Web.HttpUtility]::UrlEncode($redirectUri))&prompt=select_account&code_challenge=$($code_challenge)&code_challenge_method=$($code_challenge_method)"

               Add-Type -AssemblyName System.Windows.Forms

                $form = New-Object -TypeName System.Windows.Forms.Form -Property @{Width=440;Height=640}
                $web  = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{Width=420;Height=600;Url=($url -f ($RequestScope -join "%20")) }

                $DocComp  = {
                    $Global:uri = $web.Url.AbsoluteUri
                    if ($Global:uri -match "error=[^&]*|code=[^&]*") {$form.Close() }
                }
                $web.ScriptErrorsSuppressed = $true
                $web.Add_DocumentCompleted($DocComp)
                $form.Controls.Add($web)
                $form.Add_Shown({$form.Activate()})
                $form.ShowDialog() | Out-Null

                $queryOutput = [System.Web.HttpUtility]::ParseQueryString($web.Url.Query)
                $output = @{}
                foreach($key in $queryOutput.Keys){
                    $output["$key"] = $queryOutput[$key]
                }



                $authCode=$output["code"]


    #get Access Token


         $Body = @{
              client_id = $clientId
              code = $authCode
              code_verifier = $code_verifier
              redirect_uri = $redirectUri
              grant_type = "authorization_code"
          }


             $TokenObject.code          = $authCode
             $TokenObject.code_verifier = $code_verifier
             $TokenObject.redirect_uri  = $redirectUri


           # All Request types have create a Body for POST that will return a token

            $RequestSplat = @{
                Uri = $TokenEndpoint
                Method = “POST”
                Body = $Body
                UseBasicParsing = $true
            }


           #Construct parameters if they exist
           if($Proxy){ $RequestSplat.Add('Proxy', $Proxy) }
           if($ProxyCredential){ $RequestSplat.Add('ProxyCredential', $ProxyCredential) }

           $Response = Invoke-WebRequest @RequestSplat

           $ResponseJSON = $Response | ConvertFrom-Json

           #write-debug $Response

            #Expires in states how many seconds from not the token will be valid - this needs to be referenced as a proper date/time

           $ResponseJSON.expires_in  = (Get-Date).AddSeconds([int]($ResponseJSON.expires_in) ).ToUniversalTime()

           $TokenObject.expires_in    = $ResponseJSON.expires_in
           $TokenObject.access_token  = $ResponseJSON.access_token
           $TokenObject.refresh_token  = $ResponseJSON.refresh_token
    }

    end {

    return  $TokenObject

    }

}


function Refresh-Token {
<#
  Function:  Refresh-Token

  Purpose:  Refreshes a token that supports Refresh tokens

  Parameters:
                -Token     = Token object

  Example:

     Refresh-Token -token $AuthToken

#>
    [CmdletBinding()]
    param(
        [Parameter(mandatory=$true)]
        [PSCustomObject]$Token
    )


    # We have a previous refresh token.
    # use it to get a new token

   $redirectUri = $([System.Web.HttpUtility]::UrlEncode($Token.redirect_uri))


    # Refresh the token
    #get Access Token

    $body = "grant_type=refresh_token&refresh_token=$($Token.refresh_token)&redirect_uri=$($redirectUri)&client_id=$($Token.clientId)"

    $Response = $null
    try{
    $Response = Invoke-RestMethod $Token.token_endpoint  `
        -Method Post -ContentType "application/x-www-form-urlencoded" `
        -Body $body
    }
    catch{
    throw "token refresh failed"
    }

    if ($Response){

        $Token.expires_in  = (Get-Date).AddSeconds([int]($Response.expires_in) ).ToUniversalTime()
        $Token.access_token  = $Response.access_token
        $Token.refresh_token  = $Response.refresh_token

    }


}




function Create-Header(){
<#
  Function:  Create-Header

  Purpose:  To Generically produce a header for use in calling Microsoft API endpoints

  Parameters:   -Token = (Previously Created Token Object)

  Example:

     Create-Header -token $TokenObject

#>
    [CmdletBinding()]
    param(
        [Parameter(mandatory=$true)]
        [PSCustomObject]$Token
    )


           #refresh tokens about to expire
           $expirytime = ([DateTime]$Token.Expires_in).ToUniversalTime()
           #write-debug "Expiry = $($expirytime)"
           #write-debug "Current time  = $((Get-Date).AddSeconds(10).ToUniversalTime())"

            if (((Get-Date).AddSeconds(10).ToUniversalTime()) -gt ($expirytime.AddMinutes(-2)) ) {

                # Need to initiate Refresh
                Refresh-Token -Token $Token

            }


            #Add the token to headers for the request
            $Header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $Header.Add("Authorization", "Bearer "+$Token.access_token)
            $Header.Add("Content-Type", "application/json")

            #storage requests require two different keys in the header
            if ($Scope -eq "https://storage.azure.com/.default"){
                $Header.Add("x-ms-version", "2019-12-12")
                $Header.Add("x-ms-date", [System.DateTime]::UtcNow.ToString("R"))
            }

            #write-debug "header = $($Header)"


return  $Header


 }







<#
  Function:  Get-Latest

  Purpose:  Finds the latest date from a series of dates with the PowerShell pipeline

  Example:

           $Hashtable | Get-latest
#>
function Get-Latest {
    Begin { $latest = $null }
    Process {
            if ($_  -gt $latest) { $latest = $_  }
    }
    End { $latest }
}



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
function Get-AzureAPIVersions(){
param(
    [parameter( Mandatory = $true)]
    [hashtable]$header,
    [parameter( Mandatory = $true)]
    [string]$SubscriptionID
)

    $dict = @{}

    Try{
      $uri = "https://management.azure.com/subscriptions/$($SubscriptionID)/providers/?api-version=2015-01-01"
      $result = Invoke-RestMethod -Uri $uri -Method GET -Headers $Header

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


<#
  Function:  Get-Yamlfile

  Purpose:  Transforms a saved Yaml file to a Powershell Hash table

  Parameters:   -Path      = The file path for the yaml file to import.

  Example:

            $object = Get-Yamlfile `-Path "C:\templates\vmachine.yaml"
#>
function Get-Yamlfile(){
param(
    [parameter( Mandatory = $true)]
    [string]$Path
)

    $content = ''

    [string[]]$fileContent = Get-Content $path

    foreach ($line in $fileContent) { $content = $content + "`n" + $line }

    ConvertFrom-Yaml $content

}



<#
  Function:  Get-JSONfile

  Purpose:  Transforms a saved Yaml file to a Powershell Hash table

  Parameters:   -Path      = The file path for the json file to import.

  Example:

            $object = Get-JSONfile `-Path "C:\templates\vmachine.json"
#>
function Get-Jsonfile(){
param(
    [parameter( Mandatory = $true)]
    [string]$Path
)

    [string]$content = $null

    [string]$content = Get-Content -Path $path -Raw

    if ( Get-TypeData -TypeName "System.Array" ){
       Remove-TypeData System.Array # Remove the redundant ETS-supplied .Count property
    }
    # https://stackoverflow.com/questions/20848507/why-does-powershell-give-different-result-in-one-liner-than-two-liner-when-conve/38212718#38212718

    $jsonobj =  ($content  | ConvertFrom-Json )

    $AzObject = ConvertTo-HashTable -InputObject $jsonobj


    $AzObject
}



<#
  Function:  ConvertTo-Hashtable

  Author:  Adam Bertram
             https://4sysops.com/archives/convert-json-to-a-powershell-hash-table/

  Purpose:  Transforms a saved Yaml file to a Powershell Hash table

  Parameters:   -InputObject      = the json custom object file to import.

  Example:    $json | ConvertFrom-Json | ConvertTo-HashTable
#>
function ConvertTo-Hashtable {
    [CmdletBinding()]
    [OutputType('hashtable')]
    param (
        [Parameter(ValueFromPipeline)]
        $InputObject
    )

    process {
        ## Return null if the input is null. This can happen when calling the function
        ## recursively and a property is null
        if ($null -eq $InputObject) {
            return $null
        }

        ## Check if the input is an array or collection. If so, we also need to convert
        ## those types into hash tables as well. This function will convert all child
        ## objects into hash tables (if applicable)
        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
            $collection = @(
                foreach ($object in $InputObject) {
                    ConvertTo-Hashtable -InputObject $object
                }
            )

            ## Return the array but don't enumerate it because the object may be pretty complex
            Write-Output -NoEnumerate $collection
        } elseif ($InputObject -is [psobject]) { ## If the object has properties that need enumeration
            ## Convert it to its own hash table and return it
            $hash = @{}
            foreach ($property in $InputObject.PSObject.Properties) {
                $hash[$property.Name] = ConvertTo-Hashtable -InputObject $property.Value
            }
            $hash
        } else {
            ## If the object isn't an array, collection, or other object, it's already a hash table
            ## So just return it.
            $InputObject
        }
    }
}




<#
  Function:  Set-AzureObject

  Purpose:  Changes aspects of the Id Property of an Azure object.  This allows
            Properties to be modified from the default values stored in templates.
            Typically this might be changing subscription or resourcegroup values
            for testing.

  Parameters:   -object        = The PowerShell custom object / Azure object to be modified
                -subscription  = The new subscription gui to deploy to


  Example:

          $object = Set-AzureObject -object $object -Subscription "2be53ae5-6e46-47df-beb9-6f3a795387b8"
#>
function Set-AzureObject(){
param(
    [parameter( Mandatory = $false)]
    [string]$Subscription,
    [parameter( Mandatory = $true)]
    [hashtable]$AzObject
)



    if ($Subscription){
      $IdString = Set-IdSubscription -IdString $AzObject.id -Subscription $Subscription
      $AzObject.id = $IdString
    }

    #return the object
     $AzureObject

}



<#
  Function: Set-IdSubscription

  Purpose:  Changes the subscription of the Id Property with an Azure object.

  Parameters:   -object        = The PowerShell custom object / Azure object to be modified
                -subscription  = The new subscription gui to deploy to


  Example:

          $object = Set-IdSubscription -object $object -Subscription "2be53ae5-6e46-47df-beb9-6f3a795387b8"
#>
function Set-IdSubscription(){
param(
    [OutputType([hashtable])]
    [parameter( Mandatory = $true)]
    [string]$Subscription,
    [parameter( Mandatory = $true)]
    [string]$IdString
)

   # write-host "Set-IdSubscription azobject type = $($AzObject.GetType())"


  #Get Id property and split by '/' subscription
    $IdArray = $IdString.split('/')

  If ($IdArray[1] -eq 'subscriptions'){
    # substitute the subscription id with the new version
    $IdArray[2] = $Subscription

    #reconstruct the Id
    $id = ""
        for ($i=1;$i -lt $IdArray.Count; $i++) {
        $id = "$($id)/$($IdArray[$i])"
    }


   $IdString = $id


  }
     $IdString
 #    }
}




<#
  Function:  Get-AzureObject

  Purpose:  Gets and Azure API compliant hash table from Azure cloud objects

  Parameters:   -apiversions   = A hashtable representing current API versions
                -authHeader    = A hashtable (header) with valid authentication for Azure Management
                -id            = An Azure object reference (string).

  Example:

             Get-Azureobject -AuthHeader $authHeader -Apiversions $AzAPIVersions -azobject $azobject
#>

function Get-AzureObject(){
param(
    [parameter( Mandatory = $true, ValueFromPipeline = $true)]
    [string]$id,
    [parameter( Mandatory = $true)]
    $authHeader,
    [parameter( Mandatory = $true)]
    $apiversions
)


Process  {
    $IDArray = ($id).split("/")

    write-debug "(function Get-AzureObject) id = $id"
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
  $objecttype  = $providertype -join "/"

  write-debug "(function Get-AzureObject) objecttype = $objecttype"

 # There are some inconsistent objects that dont have a type property - default to deriving type from the ID
  if ($null -eq $objecttype ){ $objecttype = $IDArray[$provIndex + 2]}


  #Resource Groups are also a special case without a provider
  if(($IDArray.count -eq 5)-and ($idarray[3] -eq "resourceGroups")){
    write-debug "(function Get-AzureObject) IDArray count = 5 setting objecttype = Microsoft.Resources/resourceGroups"
    $objecttype = "Microsoft.Resources/resourceGroups"
  }


  # Subscriptions are special too
  if(($IDArray[1] -eq 'subscriptions') -and ($idarray.Count -eq 3)){
    write-debug "(function Get-AzureObject) IDArray count = 3 setting objecttype = Microsoft.Resources/subscriptions"
  $objecttype = "Microsoft.Resources/subscriptions" }


  write-debug "(function Get-AzureObject) Array Count = $($idarray.Count )"


  # We can now get the correct API version for the object we are dealing with
  # which is required for the Azure management URI

 # There is always one object that doesn't follow the pattern!!!
  # Check to make sure that the object type has a schema api version.  If not, drop back one element

  $obApiversion = $null
  try{
    $obApiversion = $($apiversions["$($objecttype)"])
      write-debug "(function Get-AzureObject) ObjectType = $($objecttype)"
        write-debug "obapiversion = $obApiversion"
  }
  catch{
    write-warning "(function Get-AzureObject) version retreival failure with $objecttype - $($Error[0].Exception.GetType().FullName)"
  }

  if ($obApiversion){
    # 99.99% of the time this is consistent and a version will have been retrieved
  }else{

    write-debug "(function Get-AzureObject) obApiversion does not exist"

    # We now know the object type
  #$objecttype
  $objecttype  =   $objecttype.SubString(0, $objecttype.LastIndexOf('/'))
  $obApiversion = $($apiversions["$($objecttype)"])
  write-debug "(function Get-AzureObject) API Version derived as $obapiversion  for type $objecttype"
  }


  $uri = "https://management.azure.com/$($id)?api-version=$($obApiversion)"
  write-debug "(function Get-AzureObject) uri = $uri"
  # A new exception for workbooks needing an additional parameter to get content
  # &canFetchContent
   if ($objecttype -eq "microsoft.insights/workbooks"){ $uri = $uri + '&canFetchContent=true'}

        try {
            Invoke-RestMethod -Uri $uri -Method GET -Headers $authHeader -TimeoutSec 150
        }
        catch {
            Write-Error "Failed to retrieve Azure object: $_"
            # Optionally handle the error further, such as logging or setting a default value
            #$object = $null
        }
  }



}



<#
  Function:  Remove-AzureObject

  Purpose:  Deletes an azure object

  Parameters:   -id            = A string ID representing an azure object.
                -authHeader    = A hashtable (header) with valid authentication for Azure Management
                -id            = An Azure object reference (string).

  Example:

             Remove-AzureObject -AuthHeader $authHeader -Apiversions $AzAPIVersions -azobject $azobject
#>
function Remove-AzureObject(){
param(
    [parameter( Mandatory = $true, ValueFromPipeline = $true)]
    [string]$id,
    [parameter( Mandatory = $true)]
    $authHeader,
    [parameter( Mandatory = $true)]
    $apiversions
)


Process  {
     $IDArray = ($id).split("/")
     # $namespace = $IDArray[6]
     # $resourcetype = $IDArray[7]

     # Find the last 'provider' element
     for ($i=0; $i -lt $IDArray.length; $i++) {
      if ($IDArray[$i] -eq 'providers'){$provIndex =  $i}
     }

     $arraykey = "$($IDArray[$provIndex + 1])/$($IDArray[$provIndex + 2])"


   #type can be overloaded - include if present
   if($IDArray[$provIndex + 4]){
     if($apiversions["$($arraykey)/$($IDArray[$provIndex + 4])"]){ $arraykey = "$($arraykey)/$($IDArray[$provIndex + 4])" }
   }

     #Resource Groups are a special case without a provider
     if($IDArray.count -eq 5){ $arraykey = "Microsoft.Resources/resourceGroups"}

     $uri = "https://management.azure.com/$($id)?api-version=$($apiversions["$($arraykey)"])"

    Invoke-RestMethod -Uri $uri -Method DELETE -Headers $authHeader

  }

}



<#
  Function:  Push-Azureobject

  Purpose:  Pushes and Azure API compliant hash table to the cloud

  Parameters:   -azobject      = A hashtable representing an azure object.
                -authHeader    = A hashtable (header) with valid authentication for Azure Management
                -azobject      = A hashtable (dictionary) of Azure API versions.
                -unescape      = may be set to $false to prevent the defaul behaviour of unescaping JSON

  Example:

             Push-Azureobject -AuthHeader $authHeader -Apiversions $AzAPIVersions -azobject $azobject
#>
function Push-Azureobject(){
param(
    [parameter( Mandatory = $true, ValueFromPipeline = $true)]
    $azobject,
    [parameter( Mandatory = $true)]
    $authHeader,
    [parameter( Mandatory = $true)]
    $apiversions,
    [parameter( Mandatory = $false)]
    [bool]$unescape=$true
)


Process  {
    $IDArray = ($azobject.id).split("/")

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
  $objecttype  = $providertype -join "/"

 # There are some inconsistent objects that dont have a type property - default to deriving type from the ID
  if ($null -eq $objecttype){ $objecttype = $IDArray[$provIndex + 2]}
  #Resource Groups are also a special case without a provider
  if($IDArray.count -eq 5){ $objecttype = "Microsoft.Resources/resourceGroups"}

  # We can now get the correct API version for the object we are dealing with
  # which is required for the Azure management URI
  $uri = "https://management.azure.com$($azobject.id)?api-version=$($apiversions["$($objecttype)"])"

   # The actual payload of the API request is simply deployed in json
   $jsonbody =  ConvertTo-Json -Depth 50 -InputObject $azobject

   if ($unescape -eq $true){
     # Invoke-RestMethod -Uri $uri -Method PUT -Headers $authHeader -Body $( $jsonbody  | % { [System.Text.RegularExpressions.Regex]::Unescape($_) })
    Invoke-RestMethod -Uri $uri -Method PUT -Headers $authHeader -Body $jsonbody
   }
   else
   {
      Invoke-RestMethod -Uri $uri -Method PUT -Headers $authHeader -Body $jsonbody
   }

  }

}


function ConvertTo-Yaml
{
<#
 .SYNOPSIS
   creates a YAML description of the data in the object
 .DESCRIPTION
   This produces YAML from any object you pass to it. It isn't suitable for the huge objects produced by some of the cmdlets such as Get-Process, but fine for simple objects
 .EXAMPLE
   $array=@()
   $array+=Get-Process wi* | Select-Object-Object Handles,NPM,PM,WS,VM,CPU,Id,ProcessName
   ConvertTo-YAML $array

 .PARAMETER Object
   the object that you want scripted out
 .PARAMETER Depth
   The depth that you want your object scripted to
 .PARAMETER Nesting Level
   internal use only. required for formatting
#>
    [OutputType('System.String')]

    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [AllowNull()]
        $inputObject,
        [parameter(Position = 1, Mandatory = $false, ValueFromPipeline = $false)]
        [int]$depth = 16,
        [parameter(Position = 2, Mandatory = $false, ValueFromPipeline = $false)]
        [int]$NestingLevel = 0,
        [parameter(Position = 3, Mandatory = $false, ValueFromPipeline = $false)]
        [int]$XMLAsInnerXML = 0
    )

    BEGIN { }
    PROCESS
    {
        # if it is null return null
        If ( !($inputObject) )
        {
            $p += 'null'
            return $p
        }

        if ($NestingLevel -eq 0) { '---' }

        $padding = [string]' ' * $NestingLevel # lets just create our left-padding for the block
        try
        {
            $Type = $inputObject.GetType().Name # we start by getting the object's type
            if ($Type -ieq 'Object[]')
            {
                #what it really is
                $Type = "$($inputObject.GetType().BaseType.Name)"
            }

            #report the leaves in terms of object type
            if ($depth -ilt $NestingLevel)
            {
                $Type = 'OutOfDepth'
            }
            elseif ($Type -ieq 'XmlDocument' -or $Type -ieq 'XmlElement')
            {
                if ($XMLAsInnerXML -ne 0)
                {
                    $Type = 'InnerXML'
                }
                else
                {
                    $Type = 'XML'
                }
            } # convert to PS Alias

            # prevent these values being identified as an object
            if (@('boolean', 'byte', 'byte[]', 'char', 'datetime', 'decimal', 'double', 'float', 'single', 'guid', 'int', 'int32',
                    'int16', 'long', 'int64', 'OutOfDepth', 'RuntimeType', 'PSNoteProperty', 'regex', 'sbyte', 'string',
                    'timespan', 'uint16', 'uint32', 'uint64', 'uri', 'version', 'void', 'xml', 'datatable', 'Dictionary`2',
                    'SqlDataReader', 'datarow', 'ScriptBlock', 'type') -notcontains $type)
            {
                if ($Type -ieq 'OrderedDictionary')
                {
                    $Type = 'HashTable'
                }
                elseif ($Type -ieq 'PSCustomObject')
                {
                    $Type = 'PSObject'
                }
                elseif ($Type -ieq 'List`1')
                {
                    $Type = 'Array'
                }
                elseif ($inputObject -is "Array")
                {
                    $Type = 'Array'
                } # whatever it thinks it is called
                elseif ($inputObject -is "HashTable")
                {
                    $Type = 'HashTable'
                } # for our purposes it is a hashtable
                elseif (!($inputObject | Get-Member -membertype Properties | Select-Object name | Where-Object name -like 'Keys'))
                {
                    $Type = 'generic'
                } #use dot notation
                elseif (($inputObject | Get-Member -membertype Properties | Select-Object name).count -gt 1)
                {
                    $Type = 'Object'
                }
            }
            write-verbose "$($padding)Type:='$Type', Object type:=$($inputObject.GetType().Name), BaseName:=$($inputObject.GetType().BaseType.Name) "

            switch ($Type)
            {
                'ScriptBlock'{ "{$($inputObject.ToString())}" }
                'InnerXML'        { "|`r`n" + ($inputObject.OuterXMl.Split("`r`n") | ForEach-Object{ "$padding$_`r`n" }) }
                'DateTime'   { $inputObject.ToString('s') } # s=SortableDateTimePattern (based on ISO 8601) using local time
                'Byte[]'     {
                    $string = [System.Convert]::ToBase64String($inputObject)
                    if ($string.Length -gt 100)
                    {
                        # right, we have to format it to YAML spec.
                        '!!binary "\' + "`r`n" # signal that we are going to use the readable Base64 string format
                        #$bits = @()
                        $length = $string.Length
                        $IndexIntoString = 0
                        $wrap = 100
                        while ($length -gt $IndexIntoString + $Wrap)
                        {
                            $padding + $string.Substring($IndexIntoString, $wrap).Trim() + "`r`n"
                            $IndexIntoString += $wrap
                        }
                        if ($IndexIntoString -lt $length)
                        {
                            $padding + $string.Substring($IndexIntoString).Trim() + "`r`n"
                        }
                        else
                        {
                            "`r`n"
                        }
                    }

                    else
                    {
                        '!!binary "' + $($string -replace '''', '''''') + '"'
                    }

                }
                'Boolean' {
                    "$(&{
                            if ($inputObject -eq $true) { 'true' }
                            else { 'false' }
                        })"
                }
                'string' {
                    $String = "$inputObject"
                    if ($string -match '[\r\n]' -or $string.Length -gt 80)
                    {
                        # right, we have to format it to YAML spec.
                        $folded = ">`r`n" # signal that we are going to use the readable 'newlines-folded' format
                        $string.Split("`n") | ForEach-Object {
                            $length = $_.Length
                            $IndexIntoString = 0
                            $wrap = 80
                            while ($length -gt $IndexIntoString + $Wrap)
                            {
                                $BreakPoint = $wrap
                                $earliest = $_.Substring($IndexIntoString, $wrap).LastIndexOf(' ')
                                $latest = $_.Substring($IndexIntoString + $wrap).IndexOf(' ')
                                if (($earliest -eq -1) -or ($latest -eq -1))
                                {
                                    $BreakPoint = $wrap
                                }
                                elseif ($wrap - $earliest -lt ($latest))
                                {
                                    $BreakPoint = $earliest
                                }
                                else
                                {
                                    $BreakPoint = $wrap + $latest
                                }

                                if (($wrap - $earliest) + $latest -gt 30)
                                {
                                    $BreakPoint = $wrap # in case it is a string without spaces
                                }

                                $folded += $padding + $_.Substring($IndexIntoString, $BreakPoint).Trim() + "`r`n"
                                $IndexIntoString += $BreakPoint
                            }

                            if ($IndexIntoString -lt $length)
                            {
                                $folded += $padding + $_.Substring($IndexIntoString).Trim() + "`r`n`r`n"
                            }
                            else
                            {
                                $folded += "`r`n`r`n"
                            }
                        }
                        $folded
                    }
                    else
                    {
                        "'$($string -replace '''', '''''')'"
                    }
                }
                'Char'     { "([int]$inputObject)" }
                {
                    @('byte', 'decimal', 'double', 'float', 'single', 'int', 'int32', 'int16', `
                        'long', 'int64', 'sbyte', 'uint16', 'uint32', 'uint64') -contains $_
                }
                { "$inputObject" } # rendered as is without single quotes
                'PSNoteProperty' { "$(ConvertTo-YAML -inputObject $inputObject.Value -depth $depth -NestingLevel ($NestingLevel + 1))" }
                'Array'    { "$($inputObject | Foreach-Object { "`r`n$padding- $(ConvertTo-YAML -inputObject $_ -depth $depth -NestingLevel ($NestingLevel + 1))" })" }
                'HashTable'{
                    ("$($inputObject.GetEnumerator() | Foreach-Object {
                                "`r`n$padding $($_.Name): " +
                                (ConvertTo-YAML -inputObject $_.Value -depth $depth -NestingLevel ($NestingLevel + 1))
                            })")
                }
                'Dictionary`2'{
                    ("$($inputObject.GetEnumerator() | Foreach-Object {
                                "`r`n$padding $($_.Key): " +
                                (ConvertTo-YAML -inputObject $_.Value -depth $depth -NestingLevel ($NestingLevel + 1))
                            })")
                }
                'PSObject' { ("$($inputObject.PSObject.Properties | Foreach-Object { "`r`n$padding $($_.Name): " + (ConvertTo-YAML -inputObject $_ -depth $depth -NestingLevel ($NestingLevel + 1)) })") }
                'generic'  { "$($inputObject.Keys | Foreach-Object { "`r`n$padding $($_): $(ConvertTo-YAML -inputObject $inputObject.$_ -depth $depth -NestingLevel ($NestingLevel + 1))" })" }
                'Object'   { ("$($inputObject | Get-Member -membertype properties | Select-Object-Object name | Foreach-Object { "`r`n$padding $($_.name): $(ConvertTo-YAML -inputObject $inputObject.$($_.name) -depth $NestingLevel -NestingLevel ($NestingLevel + 1))" })") }
                'XML'   { ("$($inputObject | Get-Member -membertype properties | Where-Object-object { @('xml', 'schema') -notcontains $_.name } | Select-Object-Object name | Foreach-Object { "`r`n$padding $($_.name): $(ConvertTo-YAML -inputObject $inputObject.$($_.name) -depth $depth -NestingLevel ($NestingLevel + 1))" })") }
                'DataRow'   { ("$($inputObject | Get-Member -membertype properties | Select-Object-Object name | Foreach-Object { "`r`n$padding $($_.name): $(ConvertTo-YAML -inputObject $inputObject.$($_.name) -depth $depth -NestingLevel ($NestingLevel + 1))" })") }
                <#
                'SqlDataReader'{ $all = $inputObject.FieldCount
                    while ($inputObject.Read()) {for ($i = 0; $i -lt $all; $i++)
                    {"`r`n$padding $($Reader.GetName($i)): $(ConvertTo-YAML -inputObject $($Reader.GetValue($i)) -depth $depth -NestingLevel ($NestingLevel+1))"}}
                #>
                default { "'$inputObject'" }
            }
        }
        catch
        {
            write-error "Error'$($_)' in script $($_.InvocationInfo.ScriptName) $($_.InvocationInfo.Line.Trim()) (line $($_.InvocationInfo.ScriptLineNumber)) char $($_.InvocationInfo.OffsetInLine) executing $($_.InvocationInfo.MyCommand) on $type object '$($inputObject)' Class: $($inputObject.GetType().Name) BaseClass: $($inputObject.GetType().BaseType.Name) "
        }
        finally { }
    }

    END { }
}


<#
.Synopsis
   Converts a PowerShell object to a Markdown table.
.Description
   The ConvertTo-Markdown function converts a Powershell Object to a Markdown formatted table
.EXAMPLE
   Get-Process | Where-Object {$_.mainWindowTitle} | Select-Object ID, Name, Path, Company | ConvertTo-Markdown

   This command gets all the processes that have a main window title, and it displays them in a Markdown table format with the process ID, Name, Path and Company.
.EXAMPLE
   ConvertTo-Markdown (Get-Date)

   This command converts a date object to Markdown table format
.EXAMPLE
   Get-Alias | Select Name, DisplayName | ConvertTo-Markdown

   This command displays the name and displayname of all the aliases for the current session in Markdown table format
#>
Function ConvertTo-Markdown {
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true
        )]
        [PSObject[]]$InputObject
    )

    Begin {
        $items = @()
        $columns = [ordered]@{}
    }

    Process {
        ForEach($item in $InputObject) {
            $items += $item

            $item.PSObject.Properties  | ForEach-Object{
                if($null -eq $_.Value){
                    if(-not $columns.Contains($_.Name) -or $columns[$_.Name] -lt $_.Value.ToString().Length) {
                        $columns[$_.Name] = $_.Value.ToString().Length
                    }
                }
            }
        }
    }



    End {
        ForEach($key in $($columns.Keys)) {
            $columns[$key] = [Math]::Max($columns[$key], $key.Length)
        }

        $header = @()
        ForEach($key in $columns.Keys) {
            $header += ('{0,-' + $columns[$key] + '}') -f $key
        }
        $header -join ' | '

        $separator = @()
        ForEach($key in $columns.Keys) {
            $separator += '-' * $columns[$key]
        }
        $separator -join ' | '

        ForEach($item in $items) {
            $values = @()
            ForEach($key in $columns.Keys) {
                $values += ('{0,-' + $columns[$key] + '}') -f $item.($key)
            }
            $values -join ' | '
        }
    }
}





Export-ModuleMember -function Get-Header, Get-Latest, Get-AzureAPIVersions, Get-AzureObject, Set-AzureObject, Push-AzureObject, Remove-AzureObject, Get-Yamlfile, Get-Jsonfile, ConvertTo-Yaml, ConvertTo-Markdown
