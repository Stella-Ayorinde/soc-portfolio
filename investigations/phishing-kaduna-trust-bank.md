# Credential Phishing – Fake "Kaduna Trust Bank" Account Suspension (Practice Scenario)

> Practice scenario from my SOC training (fictional bank and company). IP addresses use reserved example ranges.

## Summary
A staff member reported an email claiming to be from Kaduna Trust Bank, warning that their account would be suspended within 24 hours unless they "verified" their details. Header and content analysis showed the email was spoofed, sent from a rented server abroad, and designed to steal bank login credentials through a look-alike website and a malicious HTML attachment. Verdict: True Positive (credential phishing).

## Email Details
| Field | Value |
|---|---|
| Date | 16 Nov 2026, 06:12 (+01:00) |
| From (display) | "Kaduna Trust Bank Alerts" <alerts@kadunatrustbank[.]com> |
| Reply-To | kdtb.verify@gmail[.]com |
| Return-Path | bounce@kadunatrust-secure-ng[.]com |
| To | a.musa@company.ng |
| Subject | URGENT: Your account will be suspended in 24 hours |
| Real origin | vps-server.cheap-host[.]ru (203.0.113.77) |
| Authentication | SPF fail · DKIM none · DMARC fail (p=reject) |
| Link | hxxps://kadunatrust-secure-ng[.]com/login/verify.php |
| Attachment | Account_Statement.html |

## Investigation Steps
1. **Headers:** Reading the Received lines from bottom to top showed the email originated from vps-server.cheap-host[.]ru (203.0.113.77), a rented server, not from the bank's mail infrastructure.
2. **Sender addresses:** The Reply-To was a free Gmail address, so any reply would go straight to the attacker; no real bank uses Gmail. The Return-Path domain (kadunatrust-secure-ng[.]com) matched the link's domain, which identifies it as attacker-controlled infrastructure.
3. **Authentication:** SPF failed (the sending server was not authorised to send for kadunatrustbank.com), DKIM was absent (the email was not signed by the bank), and DMARC failed — together, strong evidence of spoofing.
4. **Link:** The "Verify My Account" button pointed to kadunatrust-secure-ng[.]com, a look-alike of the bank's real domain, with a /login/verify.php path typical of a credential-harvesting page.
5. **Attachment:** Account_Statement.html is a high-risk file type: opened locally in a browser, it can display a fake login page that web filters do not see, or use HTML smuggling to assemble and download malware.
6. **Content:** The message used urgency ("within 24 hours"), fear ("account will be suspended") and a generic greeting ("Dear Customer") — classic social-engineering triggers.

## MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| Phishing: Spearphishing Attachment (.html file) | T1566.001 |
| Phishing: Spearphishing Link ("Verify My Account") | T1566.002 |

## Verdict and Recommended Actions
**True Positive — credential phishing.**
- Block the sender address, the domain kadunatrust-secure-ng[.]com, the IP 203.0.113.77 and the attachment hash.
- Search all mailboxes for the same email and remove every copy.
- Check proxy/DNS logs for anyone who visited the link, and EDR for anyone who opened the attachment.
- Users who entered credentials: reset passwords and revoke active sessions. Users who opened the attachment: contain the host and escalate.

## Additional Finding
The bank's DMARC policy was p=reject, meaning the email should have been rejected — yet it reached the inbox. This suggests the email gateway is not enforcing DMARC; reported to the email team as a security gap.

## Indicators of Compromise (IOCs)
| Type | Value |
|---|---|
| Sending IP | 203.0.113.77 |
| Sending host | vps-server.cheap-host[.]ru |
| Phishing domain | kadunatrust-secure-ng[.]com |
| Phishing URL | hxxps://kadunatrust-secure-ng[.]com/login/verify.php |
| Reply-To | kdtb.verify@gmail[.]com |
| Attachment | Account_Statement.html |

## Lessons Learned
- The display name and "From" address are easy to fake; the Received headers and authentication results show the truth.
- When the Return-Path and the link share a domain, you have found the attacker's infrastructure.
- A free email service in the Reply-To of a "bank" email is a strong phishing sign.
- A DMARC "reject" policy only protects users if the receiving gateway enforces it.
