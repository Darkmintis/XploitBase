# XploitBase

A simple, practical CTF toolkit with tools that actually work.

## Features

### Quick Encode/Decode
- Base64 encode/decode
- URL encode/decode
- Hex encode/decode
- ROT13 cipher
- Text reversal

### CTF Tools
- **Hash Identifier** - Identify hash types (MD5, SHA1, SHA256, bcrypt, etc.)
- **JWT Decoder** - Decode JSON Web Tokens
- **Number Converter** - Convert between decimal, hex, binary, octal
- **Caesar Brute Force** - Brute force all 25 ROT variations
- **XOR Cipher** - XOR encrypt/decrypt with custom key
- **Text ↔ Binary/Hex** - Convert text to binary or hex and back

### Payload Generators
- **Reverse Shells** - Bash, Python, Netcat, PHP, PowerShell, Perl
- **XSS Payloads** - Common XSS attack vectors
- **SQLi Payloads** - Auth bypass, UNION based, Error based

### Quick Reference
- Common ports
- File signatures (magic bytes)
- Hash lengths
- Linux privesc commands
- Nmap scan commands
- LFI paths

## Usage

Just open `index.html` in a browser. No server required.

## Structure

```
XploitBase/
├── index.html      # Main page with all tools
├── css/
│   └── styles.css  # Styling
└── js/
    └── app.js      # All tool functionality
```

## License

MIT License - For educational purposes only.

---

Made for CTF players who need tools that work, not just commands to look at.
