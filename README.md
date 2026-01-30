# XploitBase

A lightweight, practical CTF toolkit that runs entirely in your browser. No server needed.

## Features

### Quick Encode/Decode
- Base64, URL, Hex encoding/decoding
- ROT13 cipher
- Text reversal

### CTF Tools
- **Hash Identifier** - Detect MD5, SHA1, SHA256, bcrypt, MySQL5, etc.
- **JWT Decoder** - Decode JSON Web Tokens to see header and payload
- **Number Converter** - Convert between Decimal, Hex, Binary, Octal
- **Caesar Brute Force** - Try all 25 ROT variations at once
- **XOR Cipher** - XOR encrypt/decrypt with custom key
- **Text ↔ Binary/Hex** - Convert text to binary or hex and back
- **String Analyzer** - Get entropy, charset, and pattern detection
- **Flag Decoder** - Auto-try Base64, Hex, ROT13, URL decode, reverse
- **ASCII Lookup** - Quick char/decimal/hex/binary conversion

### Payload Generators
- **Reverse Shells** - Bash, Python, Netcat, PHP, PowerShell, Perl
- **XSS Payloads** - Common cross-site scripting vectors
- **SQLi Payloads** - Auth bypass, UNION, Error-based injection
- **Wordlist Generator** - Generate password variations from base word
- **Common Paths** - Web directories, API endpoints, backup files, configs

### Quick Reference Cheatsheets
- Common ports and services
- File signatures (magic bytes)
- Hash lengths and formats
- Linux privilege escalation commands
- Nmap scan commands
- LFI/Path traversal paths
- Useful one-liners (TTY spawn, shell stabilization)
- Common encodings reference
- CTF flag formats

## Usage

Just open `index.html` in any browser. Everything works client-side.

## Files

```
XploitBase/
├── index.html   # Main page with all tools
├── styles.css   # Dark/light theme styling
├── app.js       # All tool functionality
├── LICENSE
└── README.md
```

## License

MIT License - For educational and CTF purposes only.

---

Built for CTF players who need working tools, not command references.
