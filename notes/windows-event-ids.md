# Windows Event IDs & Logon Types: SOC Cheat Sheet

## Key Security Event IDs
| Event ID | What it means | Attack it can reveal |
|---|---|---|
| 4624 | Successful logon | Account takeover, lateral movement |
| 4625 | Failed logon | Brute force, password spraying |
| 4634 | Account logged off | With 4624: how long an attacker's session lasted |
| 4648 | Logon using explicit credentials | Use of stolen/alternate credentials, lateral movement |
| 4672 | Special privileges assigned to new logon | Admin-level account in use (compromised admin = attacker with admin rights) |
| 4688 | New process created | Execution of malware or malicious commands |
| 4720 | User account created | Persistence (backdoor account) |
| 4726 | User account deleted | Defense evasion, impact |
| 4732 | Member added to security-enabled local group | Privilege escalation, persistence |
| 1102 | Audit log cleared | Covering tracks (escalate immediately) |

## Logon Types (in 4624 / 4625)
| Type | Name | Example |
|---|---|---|
| 2 | Interactive | Logging in at the keyboard |
| 3 | Network | Accessing a file share (SMB) |
| 5 | Service | A Windows service starting (usually SYSTEM) |
| 7 | Unlock | Unlocking a workstation |
| 10 | RemoteInteractive | Remote Desktop (RDP) |

## 4625 Sub Status codes
| Code | Meaning |
|---|---|
| 0xC000006A | Correct username, wrong password |
| 0xC0000064 | Username does not exist (many = username guessing) |

## Useful PowerShell
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 10
```

## Lesson learned
Most 4624 events on a PC are Type 5 (services). Filter by logon type and account before investigating.
