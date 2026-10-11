# SOC Incident Reports

SOC investigations written up as incident reports. Each report starts from raw logs or packet captures, shows the queries and filters I used, and ends with findings, MITRE ATT&CK mapping, response actions and recommendations.

**About me:** <Yugam Thakur>, aspiring SOC analyst. <Certified in Cybersecurity  ISC2 CC>

## Important: where the data comes from

All investigations use **public, simulated datasets and training exercises**. No real company data is used.

- **Splunk Boss of the SOC v3 (BOTS v3):** a fictional company ("Frothly") with staged attack scenarios mixed into generated background activity. Most of the data is normal noise, so each report separates the malicious events from it.
- **Malware-Traffic-Analysis.net exercises:** packet captures of real malware infections, analyzed in an isolated VM.

I did each investigation myself first and wrote it up in my own words. Public walkthroughs, where they exist, were only used afterwards to check what I missed.

## Report index

| # | Report | Category | Data | Key MITRE techniques | Status |
|---|---|---|---|---|---|
| 01 | [Exposed AWS access key misused for recon and attempted EC2 launch](./01-aws-access-key-exposure/report.md) | Credential compromise | BOTS v3 | T1552.001, T1078.004, T1580 | Done |
| 02 | Public S3 bucket exposure | Cloud misconfiguration | BOTS v3 | | Planned |
| 03 | Cryptomining activity | Resource hijacking | BOTS v3 | | Planned |
| 04 | SSH invalid-user / brute force | Brute force | BOTS v3 | | Planned |
| 05 | Suspicious Windows process chain | Endpoint / execution | BOTS v3 | | Planned |
| 06 | Suspicious external connections / O365 activity | Network / email | BOTS v3 | | Planned |
| 07 | Malware infection from pcap | Malware | Malware-Traffic-Analysis | | Planned |
| 08 | Malware infection from pcap | Malware | Malware-Traffic-Analysis | | Planned |
| 09 | Malware infection from pcap | Malware | Malware-Traffic-Analysis | | Planned |
| 10 | Malware infection from pcap | Malware | Malware-Traffic-Analysis | | Planned |

I update this table as each report is finished.

## What each report contains

1. **Executive summary:** readable by a non-technical manager
2. **Detection:** what alert or anomaly started the investigation
3. **Affected assets**
4. **Timeline** (all times UTC)
5. **Investigation steps:** question, query, result, conclusion, including dead ends
6. **IOCs:** IPs, domains, hashes, users, keys (defanged), with enrichment where done
7. **MITRE ATT&CK mapping**
8. **Root cause, impact, confidence and limitations:** what I could and couldn't prove
9. **Evidence:** screenshots and supporting files


## Tools

- **SIEM:** Splunk Enterprise (SPL)
- **Network analysis:** Wireshark
- **Enrichment:** VirusTotal, AbuseIPDB, whois / ARIN / RIPE / APNIC
- **Frameworks:** MITRE ATT&CK
- **Lab:** isolated virtual machine for any packet captures containing malware



## Conventions

- All times are **UTC**.
- IPs and URLs are **defanged** (`1[.]2[.]3[.]4`, `hxxps://`) and never opened from the lab host.
- Claims are labeled by evidence: what the logs show, what I infer, and what I couldn't determine.
- IP reputation lookups were run in the present against past simulated events, so they are context and not proof.

## Disclaimer

These are learning and portfolio projects built on simulated data and public training material. They are not based on any real employer or customer environment.
