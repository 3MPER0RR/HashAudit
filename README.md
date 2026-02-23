# HashAudit

CLI tool written in Ruby for dictionary-based hash analysis and password strength assessment.  
It supports multiple hashing algorithms and provides runtime statistics and entropy calculation for the cracked passwords.

---

## Features

- Supports **MD5, SHA1, SHA256, SHA512**  
- Dictionary attack mode  
- Runtime statistics: number of attempts, elapsed time  
- Password entropy calculation  

---

## Usage

### Analyze a hash using a dictionary

```bash
ruby HashAudit.rb -h HASH -f wordlist.txt -a md5
