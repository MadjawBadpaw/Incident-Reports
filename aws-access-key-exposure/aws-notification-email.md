# Evidence: AWS "Compromised Key" Notification Email

Captured from Splunk BOTS v3 (`stream:smtp`, host `matar`). Body text is reproduced as logged; the only change is that the GitHub URL is **defanged** (`hxxps://github[.]com/...`) so it can't be clicked by accident. Do not visit it.

## Message metadata

| Field | Value |
|---|---|
| Capture time (UTC) | 2018-08-20 09:16:54 (`timestamp: 2018-08-20T09:16:54.880499Z`) |
| From | Amazon Web Services <no-reply-aws@amazon.com> |
| To | bstoll@froth.ly |
| Subject | Amazon Web Services: New Support case: 5244329601 |
| Source IP / dest IP | 40.107.72.55 -> 172.31.38.181 (port 25, SMTP) |
| Authentication | SPF pass, DKIM pass, DMARC pass (amazon.com, relayed via amazonses.com) |
| Splunk host / sourcetype | matar / stream:smtp |

**Data quirk:** the email's `Date:` header says 14 Sep 2018, while the capture timestamp and one `Received` hop say 20 Aug 2018. The capture timestamp is used in the report timeline.

## Key lines (what matters for the investigation)

- Case ID **5244329601**, severity **Urgent**
- Names access key **AKIAJOGCDXJ5NW5PXUPA**, belonging to IAM user **web_admin**
- States the key and its secret are publicly available at: `hxxps://github[.]com/FrothlyBeers/BrewingIOT/blob/e4a98cc997de12bb7a59f18aea207a28bcec566c/MyDocuments/aws_credentials.bak`
- States AWS has **temporarily limited the ability to create some AWS resources**
- States that **disabling or removing the key from the public site is not sufficient**; the key must be deleted and the account reviewed

## Full body

```
Amazon Web Services has opened case 5244329601 on your behalf.

Case ID: 5244329601
Subject: Your AWS account 622676721278 is compromised
Severity: Urgent
Correspondence: Dear AWS Customer,

Your AWS Account is compromised! Please review the following notice and take immediate action to secure your account.

Your security is important to us. We have become aware that the AWS Access Key AKIAJOGCDXJ5NW5PXUPA (belonging to IAM user "web_admin") along with the corresponding Secret Key is publicly available online at hxxps://github[.]com/FrothlyBeers/BrewingIOT/blob/e4a98cc997de12bb7a59f18aea207a28bcec566c/MyDocuments/aws_credentials.bak.

This poses a security risk to your account and other users, could lead to excessive charges from unauthorized activity or abuse, and violates the AWS Customer Agreement.

Please delete the exposed credentials from your AWS account by using the instructions below and take steps to prevent any new credentials from being published in this manner again. Unfortunately, deleting the keys from the public website and/or disabling them is NOT sufficient to secure your account.

To additionally protect your account from excessive charges, we have temporarily limited your ability to create some AWS resources. Please note that this does not make your account secure, it just partially limits the unauthorized usage for which you could be charged.

Detailed instructions are included below for your convenience.

CHECK FOR UNAUTHORIZED USAGE
We strongly encourage you to immediately review your AWS account for any unauthorized AWS usage, suspect running instances, or inappropriate IAM users and policies. To check the usage, please log into your AWS Management Console and go to each service page to see what resources are being used. Please pay special attention to the running EC2 instances and IAM users, roles, and groups. You can also check for any unexpected usage on the "Bills" page in the Billing console.

https://console.aws.amazon.com/billing/home#/bill

Please keep in mind that unauthorized usage can occur in any region and that in your console you only see one region at a time. To switch between regions, you can use the dropdown in the top-right corner of the console screen.

DELETE THE KEY (ROOT ACCOUNT)
If you are not using the access key, you can simply delete it. To delete the exposed key, visit the "Security Credentials" page here: https://console.aws.amazon.com/iam/home#security_credential. Your keys will be listed in the "Access Keys" section.

DELETE THE KEY (IAM USERS)
Navigate to your IAM Users list in the AWS Management Console, here: https://console.aws.amazon.com/iam/home#users. Please select the IAM user identified above. Click on the "User Actions" drop-down menu and then click "Manage Access Keys" to show that user's active Access Keys. Click "Delete" next to the access key identified above.

ROTATE THE KEY
If your application uses the access key, you need to replace the exposed key with a new one. To do this, first create a second key (at that point both keys will be active) and modify your application to use the new key.
Then disable (but do not delete) the first key. If there are any problems with your application, you can make the first key active again. When your application is fully functional with the first key inactive, please delete the first key.

Please follow the Best Practices of Managing your Access Keys at http://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html.

If you have any additional questions or concerns regarding this notification, please reach out to us via the AWS Support Center: https://aws.amazon.com/support.
=======================================

To contact us again about this issue, please use the following link to enter your correspondence or attach any files you think would be useful:

https://console.aws.amazon.com/support/home?#/case/?caseId=5244329601&displayId=5244329601&language=en

(If you will connect by federation, log in before following the link.)

Sincerely,
The Amazon Web Services Team

*Please note: this e-mail was sent from an address that cannot accept incoming e-mail. Please use the appropriate link above if you need to contact us again about this same issue.

Amazon Web Services, Inc. is an affiliate of Amazon.com, Inc. Amazon.com is a registered trademark of Amazon.com, Inc. or its affiliates.
```

*Note: the original log splits two lines mid-word ("unauthorized A" / "WS usage") because of how the SMTP stream was chunked; they are rejoined above.*
