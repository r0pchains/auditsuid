# Linux Privileged Binary Security Auditor

A lightweight, zero-dependency Python utility designed to scan Linux filesystems, identify elevated SUID/SGID binaries, and pass-verify their isolation posture against environment-poisoning attacks.

## How It Works
Traditional auditors often flag any SUID/SGID binary as a flat vulnerability risk. This tool takes a precise, dual-layer approach:
1. **Asset Discovery:** Crawls core system execution paths (`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`) to inventory all elevated privileges.
2. **Posture Verification:** Uses a non-destructive runtime `ldd` verification check to confirm whether the Linux kernel and dynamic linker successfully enforce `AT_SECURE` boundaries. 

By verifying that the dynamic loader strips out dangerous variables (like `LD_PRELOAD`), the tool eliminates common privilege-dropping false positives (such as native capture utilities or PAM helpers).

## Usage
Run the audit locally:
```bash
python3 sys_audit.py
```

## Disclaimer
This project is intended strictly for configuration compliance auditing and defensive security research.
