# mailu-scaleway
Deploying your email server on Scaleway in a few minutes! **Note:** this script is cloud agnostic.

You should disable IPv6 as it is not being used here (see Mailu FAQ
https://mailu.io/master/faq.html#how-to-make-ipv6-work)

# Prerequisites
- Rent a Scaleway debian instance (Stardust at ~3 € or DEV1-S at ~9 € per month).
- Make sure its IPv4 is not blacklisted: https://mxtoolbox.com/blacklists.aspx
- Own a domain name pointing to your instance (see [Set DNS records](README.md#set-dns-records) section below).

# Installation
```
wget https://raw.githubusercontent.com/Amodio/mailu-scaleway/main/main.sh
vi main.sh # configure your settings by replacing: USER, YOUR_HOME.IP & EXAMPLE.COM.
bash main.sh
```

This script should execute in ~5 minutes and will display your credentials once.

It will deploy an email server (SPF/DKIM & DMARC) from Mailu docker images.


It will also create a `~/save.sh` script to backup your docker volumes.

To restore a backup on a fresh server, place your archive in `/root` before running this script.

# Set/create the DNS records
- `MX`  DNS entry pointing to `mail.EXAMPLE.COM`
- `CAA` DNS entry with value `letsencrypt.org` (flag: 0 / non-critical)
- `A`   DNS entry making `mail.EXAMPLE.COM` point to your server instance's IPv4

You should also set your reverse DNS on the IPv4.

For SPF:
- `TXT` DNS entry on @ (= `EXAMPLE.COM`) with value `v=spf1 ip4:IPV4_OF_YOUR_INSTANCE -all` (replace the IP)

For DMARC:
- `TXT` DNS entry on the subdomain *_dmarc* with value `v=DMARC1; p=reject; rua=mailto:admin@EXAMPLE.COM; ruf=mailto:admin@EXAMPLE.COM; adkim=s; aspf=s` (replace the domain name)

For DKIM you will have to run the script and follow its instructions to generate keys (in the web interface).
- `TXT` DNS entry on the subdomain *dkim._domainkey* with value `v=DKIM1; k=rsa; p=[...]`.

# Configure email client(s)
```
IMAP: mail.EXAMPLE.COM / port 993 (TLS)
SMTP: mail.EXAMPLE.COM / port 465 (TLS)
```
You can check https://mail.EXAMPLE.COM/mailu-admin/ui/client (replace the domain name)

# Tests
https://www.mail-tester.com

https://mxtoolbox.com/deliverability

https://mxtoolbox.com/emailhealth
