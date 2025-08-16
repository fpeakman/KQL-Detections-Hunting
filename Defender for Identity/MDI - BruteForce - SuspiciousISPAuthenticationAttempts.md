# Elevated failed authentication attempts from ISP

## Description
This query detects a high % of failed sign-in attempts from individual ISP to identify malicious activity from actors who use multiple IPs from the same ISP.

### MITRE ATT&CK

[T1110 Brute Force](https://attack.mitre.org/techniques/T1110/)

### KQL

```KQL
IdentityLogonEvents
| summarize 
    Different_IPs = make_set(IPAddress), 
    Total_different_IPs = dcount(IPAddress), 
    Total_sign_attempts = count(), 
    Suspicious_Sign_attempt = countif(
        (ActionType has "OldPassword") or 
        (FailureReason has "WrongPassword") or 
        (FailureReason has "validating credentials due to invalid username or password.") or 
        (FailureReason has "The account is locked, you've tried to sign in too many times with an incorrect user ID or password.") or 
        (FailureReason has "Authentication failed.") or 
        (FailureReason has "UnknownUser") or 
        (FailureReason has "The user account is disabled.")
    ),
    Success_Sign_attempt = countif(ActionType has "LogonSuccess"),
    Issues_Sign_attempt = countif(
        (FailureReason has "The session is not valid due to password expiration or recent password change.") or 
        (FailureReason has "General failure")
    ) 
    by ISP, Location
| extend SuspiciousRatio = Suspicious_Sign_attempt * 1.0 / Total_sign_attempts 
| where SuspiciousRatio > 0.5 // This will need to be tuned to your environment