# Domain Availability Checker

Small Python script that reads domain names from `domains.txt` and checks whether each name is available for both `.com` and `.no` using WHOIS lookups.

## What It Does
- Reads one domain per line from `domains.txt`
- Checks availability for `.com` and `.no`
- Writes domains that are free in both extensions to `free.txt`
- Writes all other domains to `not-free.txt`
- Prints a per-domain result and a short summary in the terminal

## Run
```bash
python domains.py
```
