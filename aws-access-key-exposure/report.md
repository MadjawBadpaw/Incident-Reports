# IR-001: Exposed AWS Access Key Misused for Reconnaissance and Attempted Mass EC2 Launch

| Field | Detail |
|---|---|
| Report ID | IR-001 |
| Data source | Splunk BOTS v3 (simulated dataset, fictional company "Frothly") |
| Analyst | Yugam Thakur |
| Date investigated | 2026-10-11 |
| Incident date (in dataset) | 2018-08-20, 09:16 to 09:36 UTC |
| Severity | **High** |
| Category | Credential compromise: exposed secret used by unauthorized parties |
| Status | Contained (key disabled). Remediation items open (see section 9) |
| Tools | Splunk Enterprise (SPL), VirusTotal, AbuseIPDB, ARIN / RIPE / APNIC whois |
| Time zone | All times are **UTC**. Splunk was set to UTC for every screenshot |

**Severity rationale:** the credential was publicly exposed, was used from four separate hosts within about 12 minutes, and was used for reconnaissance, attempted account manipulation (new user and access key) and about 576 attempted EC2 launches across 15 regions. It rates High, not Critical, because every privileged action failed and no successful launches or changes were observed.

---

## 1. Executive summary

An AWS access key belonging to the IAM user `web_admin` was published in a public GitHub repository, according to an automated AWS notification found in Frothly's email traffic. At 09:16:12 UTC on 2018-08-20 the key began being used from four different internet addresses in four countries. The activity included identity checks, failed attempts to create a new user and access key, and a script-like sweep of roughly 576 attempts to launch large EC2 servers in 15 AWS regions. Every launch attempt failed, and the only calls that succeeded were harmless identity checks, so no resources were created and no data access was observed. A Frothly responder ran an incident-response tool at 09:30:53 and manually disabled the key at 09:36:12, 20 minutes after the first abuse. The key is disabled but not yet deleted, and the exposure source and AWS account still need cleanup and review.

## 2. Key questions answered

| Question | Answer | Confidence |
|---|---|---|
| **What happened?** | A leaked long-term access key (`AKIAJOGCDXJ5NW5PXUPA`) was used by unauthorized parties for recon and attempted resource creation | High |
| **Who / what was affected?** | IAM user `web_admin` in AWS account 622676721278 | High |
| **When?** | First abuse 09:16:12 UTC, last observed attacker activity 09:28:54 UTC, key disabled 09:36:12 UTC (2018-08-20) | High |
| **From where?** | Four IPs: Ashburn (US), Beijing (CN), Kyiv (UA), Saint-Denis / Paris (FR). Three of the four are data-center or hosting ranges | High (IPs), Low (attribution) |
| **How did the key leak?** | Per AWS's notice, committed to a public GitHub repo in a file named `aws_credentials.bak`. I did not verify the repo | Medium (relies on AWS's statement) |
| **What was the impact?** | No successful launches, user creation or key creation observed. Only successful calls were 15 `GetCallerIdentity` checks | High |
| **What was the intent?** | Consistent with resource hijacking (mass launch of large instances), but not proven | Medium-Low |
| **How was it contained?** | `aws_ir` tool run 3 times (09:30:53 to 09:35:01), then `bstoll` set the key to Inactive in the console at 09:36:12 | High |

## 3. Detection

- **Trigger:** AWS emailed Frothly (`stream:smtp`, to bstoll@froth.ly, captured at 09:16:54 UTC) saying the access key and its secret were publicly available on GitHub. Support case 5244329601. The full email is in [`aws-notification-email.md`](./aws-notification-email.md).
- **Email authenticity:** the message passed SPF, DKIM and DMARC for amazon.com (relayed through amazonses.com).
- **In CloudTrail (`aws:cloudtrail`):** one long-term key (`AKIA...`) appeared from three unrelated IPs and tools within minutes, followed by temporary credentials (`ASIA...`) used from a fourth IP. This is a strong anomaly for a service-style user.
- **Time to AWS notice:** the notice was captured 42 seconds after the first malicious call. The exposure on GitHub therefore happened before 09:16:12; the exact commit time is not in this data.

## 4. Affected assets

| Asset | Type | Detail | Impact |
|---|---|---|---|
| IAM user `web_admin` | AWS identity | Account 622676721278, principal AIDAJNUCQVD57VVGYEFTQ | Credential exposed and used by others |
| Access key `AKIAJOGCDXJ5NW5PXUPA` | Long-term credential | Belongs to `web_admin` | Exposed publicly, misused, later disabled |
| Access key `ASIAZB6TMXZ7LL6JBJQA` | Temporary STS credential | Issued from the key above via `GetSessionToken` | Used for the EC2 launch sweep |
| EC2 service, 15 regions | Compute | Targeted by `RunInstances` | ~576 attempts, all failed |
| GitHub repo FrothlyBeers/BrewingIOT | Source repository | Per AWS email, file `MyDocuments/aws_credentials.bak` | Source of exposure (unverified by me) |
| User `bstoll` | IAM user (responder) | Received the AWS notice and disabled the key | Console session had no MFA |

## 5. Timeline (UTC, 2018-08-20)

| Time | Event | Source |
|---|---|---|
| 09:16:12 | `web_admin` key used from 35[.]153[.]154[.]221 (Boto3 on Linux): `GetCallerIdentity`, `ListAccessKeys`, `GetSessionToken`. `CreateUser`, `CreateAccessKey` and `DeleteAccessKey` all denied (`AccessDenied`) | aws:cloudtrail |
| 09:16:12 | `GetSessionToken` issues temporary credentials `ASIAZB6TMXZ7LL6JBJQA` | aws:cloudtrail |
| 09:16:14 | Temporary credentials first used from 139[.]198[.]18[.]205: `GetCallerIdentity`, `DescribeInstances`, `DescribeKeyPairs`, `CreateDefaultVpc`, `RunInstances` | aws:cloudtrail |
| 09:16:18 | Long-term key used from 209[.]107[.]196[.]112 (Boto3 on Windows Server 2012 R2): `ListAccessKeys` denied | aws:cloudtrail |
| 09:16:22 | First `RunInstances` failure recorded (`InstanceLimitExceeded`) | aws:cloudtrail |
| 09:16:54 | AWS "compromised key" notification delivered to bstoll@froth.ly | stream:smtp |
| 09:18:04 | Temporary key: `ListBuckets` denied | aws:cloudtrail |
| 09:25:58 to 09:26:40 | Burst of `InsufficientInstanceCapacity` errors (7 events, all `ap-south-1`) | aws:cloudtrail |
| 09:27:06 | Long-term key used from 82[.]102[.]18[.]111 (ElasticWolf 5.1.6): `GetUser`, `DescribeAccountAttributes` denied | aws:cloudtrail |
| 09:28:54 | Last observed activity from the temporary key | aws:cloudtrail |
| 09:30:53 | `aws_ir key-compromise ... --plugins disableaccess_key` run on host `mars.i-08e52f8b5a034012d` (run 1 of 3) | osquery:results |
| 09:33:59 | `aws_ir` run 2 | osquery:results |
| 09:35:01 | `aws_ir` run 3 | osquery:results |
| 09:35:27 | `bstoll` console session starts from 157[.]97[.]121[.]132 (no MFA) | aws:cloudtrail |
| 09:36:12 | `UpdateAccessKey` by `bstoll`: key `AKIAJOGCDXJ5NW5PXUPA` set to **Inactive** | aws:cloudtrail |

### Response metrics

| Metric | Value |
|---|---|
| Duration of observed attacker activity | 12 min 42 s (09:16:12 to 09:28:54) |
| First abuse to AWS notice | 42 s |
| First abuse to first containment attempt (`aws_ir`) | 14 min 41 s |
| First abuse to confirmed key disable | 20 min 00 s |
| Last attacker activity to confirmed key disable | 7 min 18 s |

## 6. Investigation steps

Each step is a question, the query, what it showed, and why I moved on.

### Step 1: What kinds of API calls exist in this account?

Before hunting I needed to know what normal looks like.

```spl
index=botsv3 sourcetype=aws:cloudtrail earliest=0
| stats count by eventName
| sort - count
```

Most of the volume is automated noise: AWS Config compliance checks, Inspector scans, and read-only `Describe*` / `Get*` calls. The rare, security-sensitive events at the bottom of the list (`CreateUser`, `CreateAccessKey`, `ConsoleLogin`, `PutBucketAcl`) were where I looked next.

![Event names by count, top of list](./screenshots/01-eventnames.png)
![Event names, middle of list](./screenshots/01-eventnames-2.png)
![Event names, rare events at the bottom](./screenshots/01-eventnames-3.png)

### Step 2: Which sensitive identity or security-changing events occurred?

```spl
index=botsv3 sourcetype=aws:cloudtrail earliest=0 eventName IN (ConsoleLogin, CreateUser, CreateAccessKey, DeleteAccessKey, AuthorizeSecurityGroupIngress, PutBucketAcl)
| table _time eventName userIdentity.type userIdentity.userName userIdentity.arn sourceIPAddress userAgent errorCode
| sort _time
```

Finding: `web_admin` made three IAM-changing calls (`CreateUser`, `CreateAccessKey`, `DeleteAccessKey`) within one second at 09:16:12, all `AccessDenied`, from a Boto3 user agent. Three IAM changes in a second points to a script. `AccessDenied` means AWS blocked them, which is the pattern of someone testing what a stolen key can do. The later `bstoll` events (`PutBucketAcl`, `AuthorizeSecurityGroupIngress`) succeeded and belong to a separate investigation (report 02).

![Sensitive events table](./screenshots/02-sensitive-events.png)

### Step 3: How was the `web_admin` key used, and from where?

```spl
index=botsv3 sourcetype=aws:cloudtrail earliest=0 userIdentity.userName=web_admin
| stats count min(_time) as first max(_time) as last values(eventName) as actions values(errorCode) as errors by userIdentity.accessKeyId, sourceIPAddress, userAgent
| eval first=strftime(first,"%F %T"), last=strftime(last,"%F %T")
```

Finding: one long-term key (`AKIA...`) was used from three IPs with three different tools in about 11 minutes. A normal service key comes from a small, stable set of hosts. A second key type (`ASIA...`, temporary) accounted for 636 events from a fourth IP (plus one more event with a differently formatted user agent, a `ListBuckets` denied).

| Key type | IP | Tool | Activity |
|---|---|---|---|
| Long-term (`AKIA`) | 35.153.154.221 | Boto3 / Linux | identity checks, `GetSessionToken`, denied IAM changes |
| Long-term (`AKIA`) | 209.107.196.112 | Boto3 / Windows Server 2012 R2 | `ListAccessKeys` denied |
| Long-term (`AKIA`) | 82.102.18.111 | ElasticWolf 5.1.6 | `GetUser`, `DescribeAccountAttributes` |
| Temporary (`ASIA`) | 139.198.18.205 | Boto3 / Linux | 636 events, mostly `RunInstances` |

![Key usage by IP and tool](./screenshots/03-key-by-ip.png)

### Step 4: Where did the temporary key come from?

```spl
index=botsv3 sourcetype=aws:cloudtrail earliest=0 eventName=GetSessionToken userIdentity.accessKeyId=AKIAJOGCDXJ5NW5PXUPA
| spath path=responseElements.credentials.accessKeyId output=temp_key
| table _time sourceIPAddress temp_key errorCode
```

Finding: one event, at 09:16:12 from 35[.]153[.]154[.]221, issued temporary key `ASIAZB6TMXZ7LL6JBJQA` with no error. Two seconds later that temporary key was in use from a different IP, 139[.]198[.]18[.]205. The raw `RunInstances` event confirms it: its session context shows `creationDate: 2018-08-20T09:16:12Z`. The credentials were created in one place and used in another. This could be one actor with several hosts or a tool handing credentials along; the logs do not say which.

![GetSessionToken linking the two keys](./screenshots/04-gettoken.png)

### Step 5: What did the temporary key try to do?

```spl
index=botsv3 sourcetype=aws:cloudtrail earliest=0 userIdentity.accessKeyId=ASIAZB6TMXZ7LL6JBJQA eventName=RunInstances
| fillnull value="SUCCESS" errorCode
| stats count by awsRegion, errorCode
| sort - count
```

The `fillnull` line matters: `stats ... by` drops events where a by-field is empty, and a successful call has no `errorCode`, so without it every success would silently vanish.

Finding: **no `SUCCESS` rows**. Every launch attempt failed, across 15 regions (576 attempts in total). One call per region and parameter set, repeated, looks like a script sweeping every region.

A raw event (eu-central-1) shows what was requested:

| Field | Value | Note |
|---|---|---|
| `instanceType` | t2.2xlarge | Large instance type |
| `minCount` / `maxCount` | 1 / 10 | Up to 10 per request |
| `imageId` | ami-af79ebc0 | Seen in the sampled event; AMI IDs are region-specific |
| `disableApiTermination` | true | Makes instances harder to terminate through the API |
| `userData` | `<sensitiveDataRemoved>` | A startup script may have been included; redacted, so unknown |
| Tag | `my_i_key` = `my_i_val` | Looks like placeholder values from sample code, suggesting a script or template |
| `mfaAuthenticated` | false | No MFA on the session |

![RunInstances results by region and error](./screenshots/05-runinstances.png)
![Raw RunInstances event](./screenshots/05-runinstances-raw.png)

### Step 6: Did the temporary key do anything successfully?

```spl
index=botsv3 sourcetype=aws:cloudtrail earliest=0 userIdentity.accessKeyId=ASIAZB6TMXZ7LL6JBJQA NOT errorCode=*
| stats count by eventName
```

Finding: 15 events, all `GetCallerIdentity`. Nothing else succeeded. `GetCallerIdentity` needs no IAM permissions, so it proves the temporary credentials were *valid* but not that they had real access. Every call that needed real permission (launching instances, listing buckets, creating users) failed.

![Successful calls by the temporary key](./screenshots/06-temp-key-success.png)

### Step 7: Does the key appear anywhere else? (root cause and response)

```spl
index=botsv3 earliest=0 AKIAJOGCDXJ5NW5PXUPA NOT sourcetype=aws:cloudtrail
| stats count by sourcetype, source, host
```

Finding: 5 events across three sourcetypes.

| Sourcetype | Host | Count | Meaning |
|---|---|---|---|
| `aws:description` | splunk.froth.ly | 1 | Splunk's own IAM user inventory. Expected, not a leak |
| `stream:smtp` | matar | 1 | The AWS notice naming the key as publicly exposed on GitHub (root cause) |
| `osquery:results` | mars.i-08e52f8b5a034012d | 3 | A Linux host ran an incident-response tool against the key (response) |

![Key appearances outside CloudTrail](./screenshots/07-key-elsewhere.png)

**The AWS notice** (sender `no-reply-aws@amazon.com`, recipient `bstoll@froth.ly`, subject "Amazon Web Services: New Support case: 5244329601"):

![AWS notification email fields](./screenshots/07b-smtp-notice.png)

**The response command**, run three times on host `mars` at 09:30:53, 09:33:59 and 09:35:01:

```
/usr/bin/python3.6 /usr/local/bin/aws_ir key-compromise --access-key-id AKIAJOGCDXJ5NW5PXUPA --plugins disableaccess_key
```

![aws_ir process events](./screenshots/07c-aws-ir.png)

Caveats: the email only tells me where AWS *says* the key was exposed; I did not visit or verify the repository. The email's `Date:` header says 14 Sep 2018 while the capture timestamp and one `Received` hop say 20 Aug 2018, so the timeline uses the capture timestamp. I also cannot tell from the logs why `aws_ir` ran three times.

### Step 8: How did the error codes progress over time?

```spl
index=botsv3 sourcetype=aws:cloudtrail earliest=0 userIdentity.accessKeyId=ASIAZB6TMXZ7LL6JBJQA eventName=RunInstances
| stats count min(_time) as first max(_time) as last by errorCode
| eval first=strftime(first,"%F %T"), last=strftime(last,"%F %T")
```

| Error | Count | First (UTC) | Last (UTC) |
|---|---|---|---|
| `Client.InstanceLimitExceeded` | 280 | 09:16:22 | 09:28:49 |
| `Client.UnauthorizedOperation` | 185 | 09:16:45 | 09:28:54 |
| `Client.Unsupported` | 104 | 09:16:28 | 09:28:43 |
| `Server.InsufficientInstanceCapacity` | 7 | 09:25:58 | 09:26:40 |

Finding: the first three overlap from about 09:16 to 09:28, so the logs **cannot separate** AWS resource limits, the AWS restriction mentioned in its email, and the key's own IAM permissions. I do not claim which one caused the denials. `InsufficientInstanceCapacity` is a short, separate burst (about 42 seconds, all in `ap-south-1`), meaning AWS had no capacity for that instance type there at that moment. The total is 576 attempts.

![Error codes over time](./screenshots/08-error-progression.png)

### Step 9: Was the key disabled, and by whom?

```spl
index=botsv3 sourcetype=aws:cloudtrail earliest=0 eventName=UpdateAccessKey
| spath path=requestParameters.status output=new_status
| spath path=requestParameters.accessKeyId output=key
| table _time userIdentity.userName key new_status sourceIPAddress errorCode
```

Finding: one event. At 09:36:12 UTC, `bstoll` (console session created 09:35:27, from 157[.]97[.]121[.]132, no MFA) set `AKIAJOGCDXJ5NW5PXUPA` to `Inactive` for user `web_admin`. No error code, so it succeeded. The key was **disabled, not deleted**.

![UpdateAccessKey result](./screenshots/09-updateaccesskey.png)
![Raw UpdateAccessKey event](./screenshots/09b-updateaccesskey-raw.png)

## 7. Indicators of compromise (IOCs)

All IPs are defanged. No file hashes or domains were observed in this incident.

### Credentials and identities

| Type | Value | Context |
|---|---|---|
| Access key (long-term) | AKIAJOGCDXJ5NW5PXUPA | Exposed key for user `web_admin` |
| Access key (temporary) | ASIAZB6TMXZ7LL6JBJQA | STS credentials issued from the key above at 09:16:12 |
| IAM user | web_admin (principal AIDAJNUCQVD57VVGYEFTQ) | Owner of the exposed key |
| AWS account | 622676721278 | Frothly account |

### Network indicators

| IP (defanged) | First seen (UTC) | Used with | Activity |
|---|---|---|---|
| 35[.]153[.]154[.]221 | 09:16:12 | Long-term key | Identity checks, `GetSessionToken`, denied `CreateUser` / `CreateAccessKey` / `DeleteAccessKey` |
| 139[.]198[.]18[.]205 | 09:16:14 | Temporary key | ~637 events including the 576 `RunInstances` attempts |
| 209[.]107[.]196[.]112 | 09:16:18 | Long-term key | `ListAccessKeys` denied |
| 82[.]102[.]18[.]111 | 09:27:06 | Long-term key | `GetUser`, `DescribeAccountAttributes` denied |

### User agents

| User agent | Seen from |
|---|---|
| Boto3/1.7.44 Python/2.7.12 Linux/4.4.0-1063-aws Botocore/1.10.44 | 35[.]153[.]154[.]221 |
| Boto3/1.7.42 Python/2.7.12 Linux/4.4.0-131-generic Botocore/1.10.42 | 139[.]198[.]18[.]205 |
| Boto3/1.6.3 Python/2.7.14 Windows/2012ServerR2 Botocore/1.9.3 | 209[.]107[.]196[.]112 |
| ElasticWolf/5.1.6 | 82[.]102[.]18[.]111 |

### Other artifacts

| Type | Value | Context |
|---|---|---|
| URL (per AWS email, not visited) | hxxps://github[.]com/FrothlyBeers/BrewingIOT/blob/e4a98cc997de12bb7a59f18aea207a28bcec566c/MyDocuments/aws_credentials.bak | Reported location of the exposed credentials |
| Instance parameters | t2.2xlarge, ami-af79ebc0 (sampled eu-central-1 event), tag `my_i_key=my_i_val` | Launch request pattern |
| CloudTrail eventID | b5c629fe-277c-4822-bbb1-bafc02b65e6b | Sampled denied `RunInstances` (eu-central-1) |
| CloudTrail eventID | 9df2f306-88a7-482b-8271-5930366a7fa7 | `UpdateAccessKey` (containment) |

### Responder context (not indicators of compromise)

| Value | Context |
|---|---|
| 157[.]97[.]121[.]132 | `bstoll` console session that disabled the key |
| host `mars.i-08e52f8b5a034012d` | Linux host that ran `aws_ir` |

## 8. Threat intelligence enrichment

I looked up each IP in VirusTotal, AbuseIPDB and whois (ARIN, RIPE, APNIC) on 2026-10-11.

**Important caveat:** these are 2026 lookups on 2018 simulated events. Ownership, reputation and reassignments may have changed, and a clean score does not clear an IP. I treat enrichment as context, not proof. Where a registry record shows a date, I note whether it existed in 2018.

### Summary

| IP | Owner / ASN | Country | Type | VirusTotal | AbuseIPDB |
|---|---|---|---|---|---|
| 35[.]153[.]154[.]221 | Amazon.com, Inc. (AS14618) | US (Ashburn, VA) | Data center / hosting | 0 vendors flagged | Not in database, 0 reports, 0% |
| 139[.]198[.]18[.]205 | Yunify Technologies Inc. (AS59078) | CN (Beijing) | Data center / hosting | 0 vendors flagged | Not in database, 0 reports, 0% |
| 209[.]107[.]196[.]112 | Strong Technology, LLC (AS62651) | UA (Kyiv) | Commercial | 0 vendors flagged | **73 reports**, 0% confidence |
| 82[.]102[.]18[.]111 | M247 Europe SRL (AS9009) | FR (Saint-Denis, Paris) | Data center / hosting | 0 vendors flagged | **6 reports**, 0% confidence |

### Per-IP detail

**35[.]153[.]154[.]221 (long-term key: identity checks, `GetSessionToken`, denied IAM changes)**
- **VirusTotal:** no vendor flagged it as malicious. Network 35.153.0.0/16, AS14618 (Amazon.com, Inc.), US. Last analysis about 1 year ago.
- **Whois (ARIN):** NetRange 35.152.0.0 to 35.183.255.255, NetName AT-88-Z, organization Amazon Technologies Inc., Seattle, WA. Registered 2016-08-09, so the allocation existed at the time of the incident. The abuse contact is Amazon EC2 Abuse.
- **AbuseIPDB:** not found in the database. 0 reports, 0% confidence. ISP Amazon Data Services Northern Virginia, usage type Data Center/Web Hosting/Transit, hostname `ec2-35-153-154-221.compute-1.amazonaws.com`, Ashburn, Virginia.
- **Read:** an AWS EC2 address. This is the host that created the temporary credentials, and it appears to be rented cloud compute. Anyone can rent an EC2 address, so ownership tells me nothing about who used it.

**139[.]198[.]18[.]205 (temporary key: ~637 events, all `RunInstances` sweeps)**
- **VirusTotal:** no vendor flagged it. Network 139.198.16.0/20, AS59078 (Yunify Technologies Inc.), CN. Last analysis about 2 years ago.
- **Whois (APNIC):** inetnum 139.198.0.0 to 139.198.255.255, NetName YUNIFY-NET, Yunify Technologies Inc., Beijing, CN. Route object 139.198.0.0/16 with origin AS59078 was last modified 2018-01-18, so it existed before the incident. Abuse contact is a Yunify IRT mailbox.
- **AbuseIPDB:** not found in the database. 0 reports, 0% confidence. Usage type Data Center/Web Hosting/Transit, Beijing.
- **Read:** a hosting range in China. It is the busiest source in the incident, and it is a different provider and country from the host that created the credentials.

**209[.]107[.]196[.]112 (long-term key: denied `ListAccessKeys`, Windows host)**
- **VirusTotal:** no vendor flagged it. Network 209.107.196.0/24, AS62651 (Strong Technology, LLC), UA. Last analysis about 7 months ago.
- **Whois (ARIN):** the parent block 209.107.195.0 to 209.107.196.255 (NETPR-14) belongs to Netprotect, Inc., New York. The 209.107.196.0/24 block was **reassigned on 2022-03-09** to a customer (NETPR-IEV-DP) with a Kyiv, Ukraine address, last updated 2024-01-05. **That reassignment is after the 2018 incident**, so I cannot say who held this IP in 2018.
- **AbuseIPDB:** found, **reported 73 times**, but confidence of abuse is 0%. ISP Strong Technology, LLC, usage type Commercial, hostname `209-107-196-112.kbp.as62651.net`, Kyiv. I did not check the report categories or dates; the 73 reports could be anything from port scans to spam, and a follow-up would be to read them.
- **Read:** the only IP with a meaningful report history, but a 0% score and a post-2018 ownership change make it weak evidence either way.

**82[.]102[.]18[.]111 (long-term key via ElasticWolf: `GetUser`, `DescribeAccountAttributes`)**
- **VirusTotal:** no vendor flagged it. Network 82.102.16.0/20, AS9009 (M247 Europe SRL), FR. Last analysis about 1 year ago.
- **Whois (RIPE):** inetnum 82.102.18.0 to 82.102.18.255, NetName M247-LTD-Paris, "M247 LTD Paris Infrastructure". Created 2017-09-26 and last modified 2018-12-03, so the allocation existed at the time of the incident. Route 82.102.18.0/24 originates from AS9009.
- **AbuseIPDB:** found, **reported 6 times**, confidence of abuse 0%. ISP M247 LTD Paris Infrastructure, usage type Data Center/Web Hosting/Transit, domain m247global.com, Saint-Denis.
- **Read:** a European hosting range.

### What the enrichment adds

- **Four countries, four providers.** The activity came from US, Chinese, Ukrainian-customer and French infrastructure. Three are data-center or hosting ranges and the fourth is registered as commercial. That spread is consistent with rented infrastructure but also with ordinary cloud workloads, so it is context, not attribution.
- **A clean score is not clearance.** All four IPs came back with zero vendor detections in VirusTotal. VirusTotal's "last analysis" dates range from 7 months to 2 years ago, so the results may be stale. Freshly rented infrastructure often has no reputation history.
- **Reports are not proof either.** Two IPs have AbuseIPDB reports (73 and 6), but both show 0% confidence of abuse.
- **Registry dates matter.** For three of the four IPs, the registry record predates the incident (2016, 2018, 2017). For the Kyiv block, the reassignment postdates it, so ownership then is unknown.
- **Action in a real SOC:** AWS asks that abuse reports include source IP, destination IP, destination port, an accurate timestamp with timezone, and a short log extract. For the AWS-hosted IP (35.153.154.221), I would send those to Amazon EC2 Abuse with the 09:16:12 UTC activity.

## 9. MITRE ATT&CK mapping

IDs should be double-checked against attack.mitre.org before publishing.

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 | Key reportedly stored in `aws_credentials.bak` in a public repo (per AWS) |
| Initial Access / Persistence | Valid Accounts: Cloud Accounts | T1078.004 | Legitimate `web_admin` key used by unauthorized parties |
| Discovery | Account Discovery: Cloud Account | T1087.004 | `GetCallerIdentity`, `GetUser`, `ListAccessKeys` |
| Discovery | Cloud Infrastructure Discovery | T1580 | `DescribeInstances`, `DescribeKeyPairs`, `DescribeAccountAttributes` |
| Discovery | Cloud Storage Object Discovery (attempted) | T1619 | `ListBuckets`, denied |
| Persistence | Create Account: Cloud Account (attempted) | T1136.003 | `CreateUser`, denied |
| Persistence | Account Manipulation: Additional Cloud Credentials (attempted) | T1098.001 | `CreateAccessKey`, denied |
| Impact | Resource Hijacking (attempted, not confirmed) | T1496 | 576 `RunInstances` attempts for large instances; intent not proven |

## 10. Root cause and impact

**Root cause:** per AWS's notification, the access key and its secret were committed to a public GitHub repository in a credentials backup file (`aws_credentials.bak`). I could not verify the repository directly, and the commit time is not in this data.

**Impact:**
- No successful EC2 launches or resource changes were observed in CloudTrail.
- The only successful calls from the temporary key were 15 `GetCallerIdentity` checks.
- Attempts to create a new IAM user and access key were denied, so no persistence was established through those calls.
- The attacker learned that the key is valid, the account ID, and the user name.
- No cost impact was observed, because no instances launched.

**Confidence:** high that the key was used by unauthorized parties; medium on intent (mass launch of large instances is consistent with resource hijacking but not proven); low on how long the key had been public before first use.

**Limitations and open questions:**
- The `userData` in launch requests is redacted, so the launch script is unknown.
- The four IPs may be one actor using several hosts, or several actors. I found no evidence to say which.
- I could not separate AWS's resource restriction from the key's own permissions as the cause of the denials (Step 8).
- `aws_ir` ran three times before the key was disabled manually, and the logs do not say why.
- The GitHub repository and the commit time were not verified.
- The key's activity before 09:16:12 UTC is not in this data.
- Follow-up not done: read the AbuseIPDB report categories for 209.107.196.112 and 82.102.18.111.

## 11. Response (what I would do in a real SOC)

- **Contain:** the key was disabled at 09:36:12 UTC (done). Revoke any active STS sessions for `web_admin` by attaching an inline policy that denies actions for sessions issued before a cutoff time. Block the four IPs at the perimeter if they touch Frothly infrastructure.
- **Eradicate:** delete (not just disable) the exposed key. Remove the secret from the repository and from its **git history**, and treat it as permanently compromised. Audit every region for unexpected EC2 instances, IAM users, roles, access keys and policy changes since 09:16 UTC. Check the billing console for unexpected charges.
- **Recover:** create a replacement credential only if one is needed and store it in a secrets manager. Reply to AWS support case 5244329601 once the account has been reviewed.
- **Escalate / notify:** escalate to Tier 2 and the cloud owner. Notify the owner of the repository. Report abuse for the AWS-hosted IP using the details in section 8. Involve legal or privacy teams if account data may have been exposed.

## 12. Recommendations and detection ideas

**Prevent:**
- Turn on secret scanning and push protection for all repositories, and add a pre-commit scanner such as gitleaks or git-secrets.
- Never keep credentials in `.bak` or similar files, or in source control.
- Replace long-term access keys with IAM roles and short-lived credentials where possible.
- Enforce MFA for console users, including those allowed to disable keys (`bstoll`'s session had no MFA).
- Apply least privilege to service users: `web_admin` should not hold broad IAM or EC2 permissions it does not need.

**Detect** (starting points, to be tuned):

One access key used from many IPs or user agents in a short window:
```spl
index=botsv3 sourcetype=aws:cloudtrail
| stats dc(sourceIPAddress) as ips dc(userAgent) as agents values(sourceIPAddress) as ip_list by userIdentity.accessKeyId
| where ips > 2
```

`RunInstances` across many regions from one key:
```spl
index=botsv3 sourcetype=aws:cloudtrail eventName=RunInstances
| stats dc(awsRegion) as regions count by userIdentity.accessKeyId
| where regions > 5
```

Also alert on:
- Bursts of IAM-changing calls (`CreateUser`, `CreateAccessKey`) ending in `AccessDenied`.
- `GetSessionToken` followed by use of the new credentials from a different source IP.
- AWS "compromised key" notices arriving in the mailbox. Route them to a ticket queue automatically.

