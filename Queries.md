//Brute force Detection

SigninLogs
|where ResultType != 0
|summarize FailedAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
|where FailedAttempts > 10
|sort by FailedAttempts desc

## Password Spray Detection

SigninLogs
|where ResultType != 0
|summarize UsersTargeted = dcount(UserPrincipalName) by IPAddress, bin(TimeGenerate, 5m)
|where UserTargered > 5
|sort by UserTargeted desc

## IPs with Most Failed Attempts
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by IPAddress
| sort by FailedAttempts desc

## impossible Travel Detection
SigninLogs
| where ResultType == 0
| project UserPrincipalName, IPAddress, Location, TimeGenerated
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend PreviousLocation = prev(Location), PreviousTime = prev(TimeGenerated), PreviousUser = prev(UserPrincipalName)
| where UserPrincipalName == PreviousUser
| where Location != PreviousLocation
| extend TimeDifference = TimeGenerated - PreviousTime
| where TimeDifference < 1h
| project UserPrincipalName, PreviousLocation, Location, PreviousTime, TimeGenerated, TimeDifference

## Failed Logins Followed by Success
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| join (
    SigninLogs
    | where ResultType == 0
    | project UserPrincipalName, IPAddress, SuccessTime = TimeGenerated
) on UserPrincipalName
| project UserPrincipalName, IPAddress, FailedAttempts, SuccessTime
| order by FailedAttempts desc

//SOC analysts use this detection to identify possible account takeovers and investigate suspicious login behavior.


## Day 11 – Suspicious PowerShell Detection
|where EventID == 4668
|where process has "powershell"
|where CommandLine has_any ("EncodedCommand", "Invoke-WebRequest", "DownloadString", "IEX")
|project TimeGenerated, Computer, Account, CommandLine
|sort by TimeGenerated desc
