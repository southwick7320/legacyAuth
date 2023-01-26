#complain to: Mac Edwards
#Create an Azure App with AuditLog.Read.All permission.  Admin consent required. 
#Requires -Modules ImportExcel

#Install Excel Module Install-Module ImportExcel -Scope CurrentUser
param (
    [Parameter(Mandatory=$true)]
    $ApplicationID,
    [Parameter(Mandatory=$true)]
    $TenantDomainName,
    [Parameter(Mandatory=$true)]
    $AccessSecret,
    $SPOUsername,
    $SPOPassword,
    $UploadUrl,
    $DaysBack = 7,
    $UploadtoSPO,
    $UploadFilePath 
 )


if($SPOUsername -and $SPOPassword){
    Import-module PnP.PowerShell
    $SPOCredentials = New-Object -TypeName PSCredential -ArgumentList $SPOUsername,(ConvertTo-SecureString -String $SPOPassword -AsPlainText -Force)
}
$jobstarttime = get-date

function Connect-Graph {
    param(
        $ApplicationID, 
        $TenantDomainName,
        $AccessSecret
    )
    
    $Body = @{    
        Grant_Type    = "client_credentials"
        Scope         = "https://graph.microsoft.com/.default"
        client_Id     = $ApplicationID
        Client_Secret = $AccessSecret
    } 
    
    $ConnectGraph = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantDomainName/oauth2/v2.0/token" `
    -Method POST -Body $Body
    
    $ConnectGraph

}

Write-Host "
LEGACY AUTHENTICATION CLIENTS
      [1] - AutoDiscover
      [2] - Exchange ActiveSync
      [3] - Exchange Online PowerShell      
      [4] - Exchange Web Services      
      [5] - IMAP4
      [6] - MAPI Over HTTP
      [7] - Offline Address Book
      [8] - Other clients
      [9] - Outlook Anywhere (RPC over HTTP)
      [10]- POP3      
      [11]- Reporting Web Services
      [12]- Authenticated SMTP 
      "
Write-Host "
----------------------------------------------------------------"
Function Get-LegacyAuthSignins {
    param(
    
        $applicationID ,
        $AccessSecret,
        $daysBack
    )
    #credit to "www.lab365.in"
    
    $authtype = "Authenticated SMTP","AutoDiscover","Exchange ActiveSync","Exchange Online PowerShell","Exchange Web Services","IMAP4","MAPI Over HTTP","Offline Address Book","Other clients","Outlook Anywhere (RPC over HTTP)","POP3","Reporting Web Services"
    
    $folderpath = ".\LegacyAuthLogs-$(get-date -Format MM_dd_yyyy)"
    
    $Output = @()
    foreach($dayback in 1..$daysback){

        foreach($app in $authtype){

            $startdate = get-date (Get-Date -Hour 00 -Minute 00 -Second 01).AddDays(-$dayback) -Format yyyy-MM-dd
            $enddate = get-date (Get-Date -Hour 23 -Minute 59 -Second 59).AddDays(-($dayback-1)) -Format yyyy-MM-dd
    
            $ConnectGraph = Connect-Graph -ApplicationID $applicationID -TenantDomainName $TenantDomainName -AccessSecret $AccessSecret
            $ExpirationTime =  (get-date).AddSeconds(($ConnectGraph.expires_in))
            $accesstoken = $ConnectGraph.access_token
        
            Write-Host "Sign-in Logs starting from $startdate to $enddate will be searched" -ForegroundColor Cyan

            $resultcount = 0
        
            if ($accesstoken)  { 
                Write-Host "Fetching the signin logs for $app" -ForegroundColor cyan
                $Clientappq="clientAppUsed eq " + "'"  +  $app + "'"
                $date = " and createdDateTime ge " + $startdate +  " and createdDateTime le  " + $enddate # 'YYYY-MM-DD'
                $queryFilter=$Clientappq# + $date
                $apiUrl='https://graph.microsoft.com/beta/auditLogs/signIns?' + "`$filter=$queryFilter"
                
                TRY   {
                    $Data=Invoke-RestMethod -Headers @{Authorization = "Bearer $accessToken"} -Uri $apiUrl -Method Get
                    if ($data.value){
                                    $output += $data.value | select createdDateTime,userPrincipalName,appDisplayName,clientAppUsed,userAgent,conditionalAccessStatus,
                                    @{N="operatingSystem";E={$_.deviceDetail.operatingSystem}},
                                    @{N="browser";E={$_.deviceDetail.browser}},ipAddress,authenticationRequirement,
                                    @{N="Status";E={$_.Status.errorCode}},
                                    @{N="additionalDetails";E={$_.Status.additionalDetails}},
                                    @{N="failureReason";E={$_.Status.failureReason}}# |`
                                    #export-csv $exportFileName -NoTypeInformation -Append 
                                   }
                    $resultcount += $data.value.count
        
                } CATCH {               
                       Write-Host "Failed to fetch the Sign-in logs, please review the error message below." -ForegroundColor Yellow
                      
                       if (($error[0].ErrorDetails.message | ConvertFrom-Json -ErrorAction SilentlyContinue).error.message -match "expired")
                            {
                             Write-Host "Token in psSession has expired,script will try renew the token please restart the script" -ForegroundColor Yellow
                             $Global:authResult=GetAuthorizationToken
                            } 
                       else {
                             Write-Host "Please make sure the account " -NoNewline -ForegroundColor Yellow
                             Write-Host  $Office365Username -NoNewline -ForegroundColor Cyan
                             Write-Host  " has 'Report Reader' role rights." -ForegroundColor Yellow
                             break
                            }
                }
            } 
            else {
                Write-host "Could not fetch the token.. breaking.."         
                Write-Host "Script failed due the following exception" -ForegroundColor Yellow
                $authResult.Exception.InnerException.Message
                ;break
            }
        
            #go in loop if more than 1000 Logs were found.
            if ($data."@odata.nextLink" -ne $null) {
                do {
                    #check the current auth token status.                
                    $MinToExpire=($ExpirationTime - (get-date)).minutes
                    Write-Host "AuthToken Age $MinToExpire Min " -NoNewline 
                    if($MinToExpire -lt 5) {
                        Write-host "renewing token"
                        $Global:authResult = Connect-Graph -ApplicationID $applicationID -TenantDomainName $TenantDomainName -AccessSecret $AccessSecret
                        $accessToken=$authResult.access_token
                        $ExpirationTime = (get-date).AddSeconds(($authResult.expires_in))
                    }
        
                    #Fetch the next Odata Link
                
                    $apiUrl=$data."@odata.nextLink"
                    Write-host "Log Processed so far:" $resultcount  -ForegroundColor Cyan   
                    Try{           
                        $Data=Invoke-RestMethod -Headers @{Authorization = "Bearer $accessToken"} -Uri $apiUrl -Method Get
                    } Catch {
                          
                        if(($Error[0].exception | Out-String) -like "The remote server returned an error: (429)*"){
                            Write-host "Error 429 returned, please wait 30 seconds"
                            Start-Sleep -Seconds 30
                            $apiURL = $apiURL
        
                        }elseif (($Error[0].exception | Out-String) -like "The remote server returned an error: (504) Gateway Timeout*"){
        
                            Write-host "Error 504 returned, please wait 2 minutes"
                            Start-Sleep -Seconds 120
                            $apiURL = $apiURL
        
                        } else {
        
                            $Error[0].exception
        
                        }
        
                    }
                        
                        #Export to csv
                    if ($data.value) 
                            {                           
                             $output += $data.value | select createdDateTime,userPrincipalName,appDisplayName,clientAppUsed,userAgent,conditionalAccessStatus,
                             @{N="operatingSystem";E={$_.deviceDetail.operatingSystem}},
                             @{N="browser";E={$_.deviceDetail.browser}},ipAddress,authenticationRequirement,
                             @{N="Status";E={$_.Status.errorCode}},
                             @{N="additionalDetails";E={$_.Status.additionalDetails}},
                             @{N="failureReason";E={$_.Status.failureReason}}# | `
                              $resultcount += $data.value.count
                    }                  
                } until ($data."@odata.nextLink" -eq $null)
                        
  
            }
            else { 
              #Notification for less than 1K logs 
                if ($data){
                    #Write-Host "Sign-in Logs Export completed"
                    #Write-Host "logs has has been exported to path" $(($(Get-Location).path) + "\" + "$exportFileName") -f Green
                }
            } 

        }
    
        Write-host "sleeping overnight..."
        Start-Sleep -Seconds 10
    
    }

    $output
}

Write-host "Getting Legacy Signins for $DaysBack days, this could take a while"
$Output = Get-LegacyAuthSignins -applicationID $ApplicationID -AccessSecret $AccessSecret -daysBack $DaysBack
Write-host "Legacy Authentication Count: $($output.count)"
$GroupByUser = $Output | Group-Object userprincipalname

$progressCount = 0

$UniqueEntries = $GroupByUser | ForEach-Object {
    $progressCount ++
    if(!($progressCount%100)){Write-host "Processing $progressCount of $($group.count)"}
    $upn = $_.name
    $legacyUserObject = [pscustomobject]@{
        userPrincipalName = $_.name
        appDisplayName = ($_.group.appDisplayName | sort-object -Unique ) -join ";"
        clientAppUsed = ($_.group.clientAppUsed | sort-object -Unique ) -join ";"
        userAgent = ($_.group.userAgent | sort-object -Unique ) -join ";"
        operatingSystem = ($_.group.operatingSystem| sort-object -Unique ) -join ";"
        browser = ($_.group.browser |sort-object -Unique ) -join ";"
        ipAddress =  ($_.group.ipAddress | sort-object -Unique  ) -join ";"
        MostRecentLegacyAuthAttempt = ($_.group.createdDateTime  | sort-object -Descending | select-object -First 1) 
        SuccessfullAuthentication = if(($_.group.status) -contains 0){$True}else{$False}
    }

    $legacyUserObject

}

    
    $FileDateRange = (get-date ((get-date).AddDays(-$daysBack)) -Format "MM_dd_yyyy") + "-" + (get-date -Format "MM_dd_yyyy")


    $OutputFile = ".\LegAuth_" + $FileDateRange + ".xlsx"
    $RAWOutputFile = ".\LegAuth_RAW_" + $FileDateRange + ".csv"
    $UniqueEntries | Export-Excel -Path $OutputFile
    $Output | export-csv -Path $RAWOutputFile -NoTypeInformation
    
if($UploadtoSPO -like "Yes"){
    Write-host "Connecting to $UploadUrl"
    Connect-PnPOnline -Url $UploadUrl -Credentials $SPOCredentials

    $foldername = "LegacyAuth-" + $FileDateRange
    Write-host "Creating Folder : $foldername"
    Add-PNPfolder -Name $foldername -Folder $UploadFilePath 

    Write-host "Uploading files $OutputFile and $RAWOutputFile"

    Add-PnPFile -Folder ($UploadFilePath + "/" + $foldername)  -Path $OutputFile 
    Add-PNPFile -Folder ($UploadFilePath + "/" + $foldername) -Path $RAWOutputFile

    Write-host "Deleting local files"
    Remove-Item -Path $OutputFile -Verbose
    Remove-Item -Path $RAWOutputFile -Verbose

    Disconnect-PnPOnline
    } else {
        Write-host "Not uploading to SPO"

    }


$jobendtime = get-date
Write-host "Goodbye..."
Write-host "Total run time..."
$jobendtime - $jobstarttime
