# ReverseIP

### Reverse IP / Shared-IP OSINT Tool

**Created by:** cyb3rconqu3ror  
**Version:** 1.0.0  
**Platform:** Kali Linux / Linux

ReverseIP is a free passive OSINT tool designed to discover domains associated with an IP address using publicly available DNS and OSINT sources.

It can also maintain a local SQLite database, allowing users to build and query their own Reverse IP dataset.

---

## Features

- Reverse IP lookup
- Domain → IP resolution
- IP → Domain discovery
- Passive OSINT
- HackerTarget integration
- RapidDNS integration
- Certificate Transparency (`crt.sh`) support
- DNSlytics best-effort support
- Local SQLite Reverse IP database
- CSV dataset import
- Live DNS validation
- Multi-source correlation
- Confidence scoring
- JSON export
- CSV export
- Multithreaded DNS validation
- Interactive terminal interface
- Direct command-line usage
- Global Kali Linux installation

---

<img width="1536" height="1024" alt="reverseip" src="https://github.com/user-attachments/assets/2cbf7f4f-2665-4ead-af98-145039d09eb4" />


## Disclaimer

ReverseIP is intended for **legitimate security research, OSINT, penetration testing, defensive security, and authorized reconnaissance**.

Only use ReverseIP against domains, IP addresses, and infrastructure that you are authorized to investigate.

The developer is not responsible for misuse of this tool.

### Important

An IP address can be shared by many unrelated domains.

A shared IP address **does not prove**:

- Common ownership
- Common organization
- Common infrastructure
- Common application
- Physical server relationship

ReverseIP reports technical DNS/IP associations and OSINT observations.

---

# Installation

## Requirements

- Kali Linux or another Linux distribution
- Python 3
- Internet connection

---

## Quick Installation

Clone the repository:

```bash
git clone https://github.com/Surya-TheCyberConqueror/ReverseIP.git

cd ReverseIP

chmod +x install.sh

sudo ./install.sh

reverseip

