# SOC114 – Malicious Attachment Detected (LetsDefend)

## Summary
An invoice-themed phishing email delivered a malicious attachment to richard@letsdefend.io. Log analysis confirmed the attachment was opened, 27 minutes after delivery, Richard's computer connected to a malware server through EQNEDT32.EXE (Equation Editor exploit). Verdict: True Positive — host contained and email deleted.

## Alert Details
| Field | Value |
|---|---|
| Alert | SOC114 – Malicious Attachment Detected (Event ID 45) |
| Date | 31 Jan 2021, 13:48 |
| Sender | accounting@cmail[.]carleton[.]ca (49.234.43.39) |
| Recipient | richard@letsdefend.io |
| Subject | Invoice |
| Device Action | Allowed |

## Investigation Steps
1. **Email review (Email Security):** red flags included a university domain sending a shopping invoice, the generic greeting "Dear customer", and an unexpected invoice used as a lure.
2. **Attachment analysis:** searched the attachment's MD5 hash on VirusTotal — 38/62 engines flagged it as a trojan/downloader.
3. **Contacted addresses (VirusTotal Relations):** the malware downloads a second-stage file (network.exe) and contacts dynamic-DNS domains and IPs including 5.135.143.133. Microsoft addresses (52.111.x.x, nexus.officeapps.live.com) were excluded as normal Office traffic.
4. **Delivery:** Device Action was **Allowed** — the email reached Richard's inbox.
5. **User interaction (Log Management):** filtered destination_address = 5.135.143.133 and found a connection from Richard's computer (172.16.17.45).

## Key Evidence
`2021-01-31 14:15:45 | Proxy | 172.16.17.45:53948 → 5.135.143.133:443 | Process: EQNEDT32.EXE`
- Richard's computer contacted a known malware IP 27 minutes after the email arrived.
- The connecting process was EQNEDT32.EXE (Microsoft Equation Editor), showing the attachment exploited CVE-2017-11882 when opened.

## MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| Phishing: Spearphishing Attachment | T1566.001 |
| User Execution: Malicious File | T1204.002 |
| Exploitation for Client Execution (CVE-2017-11882) | T1203 |
| Ingress Tool Transfer (download of network.exe) | T1105 |

## Verdict and Actions
**True Positive.** The attachment was malicious, delivered and opened, and the host contacted a malware server. Richard's host was contained to stop further communication or spread, the email was deleted, and the case was escalated for malware remediation.

## Indicators of Compromise (IOCs)
| Type | Value |
|---|---|
| Sender | accounting@cmail[.]carleton[.]ca |
| Sender IP | 49.234.43.39 |
| File hash (MD5) | c9ad9506bcccfaa987ff9fc11b91698d |
| Download URL | hxxp://andaluciabeach[.]net/image/network[.]exe |
| C2 IP | 5.135.143.133 |

## Lessons Learned
- Don't conclude from guesswork: confirm user interaction with log evidence before answering "opened".
- Check what a tool is reporting on: a file hash and a download link give different results in VirusTotal.
- Network logs record IP addresses, so search by IP in the correct field and clear old filters first.
- Never open a suspicious attachment during an investigation, analyse it by its hash instead.
