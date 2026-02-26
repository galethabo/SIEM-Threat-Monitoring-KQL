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

// IPs with Most Failed Attempts
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by IPAddress
| sort by FailedAttempts desc

## impossible Travel Detection
SigninLogs
|summarize Location = make_set(Location) by UserPrincipalName, bin(TimeGenerated, 1h)
!where array_length(Location) > 1
