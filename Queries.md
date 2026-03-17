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
let FailedLogins = SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by IPAddress, UserPrincipalName, bin(TimeGenerated, 10m)
| where FailedAttempts >= 5;

let SuccessfulLogins = SigninLogs
| where ResultType == 0
| summarize SuccessCount = count() by IPAddress, UserPrincipalName, bin(TimeGenerated, 10m);

FailedLogins
| join kind=inner SuccessfulLogins on IPAddress, UserPrincipalName, TimeGenerated
