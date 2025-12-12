// JWT Decoding Functions
function decodeJWT() {
    const input = document.getElementById('jwt-input').value.trim();
    const outputContainer = document.getElementById('output-container');
    const headerOutput = document.getElementById('jwt-header');
    const payloadOutput = document.getElementById('jwt-payload');
    const signatureOutput = document.getElementById('jwt-signature');
    const infoOutput = document.getElementById('jwt-info');
    
    if (!input) {
        showToast('Please enter a JWT token', 'error');
        return;
    }
    
    try {
        // Split JWT into parts
        const parts = input.split('.');
        
        if (parts.length !== 3) {
            throw new Error('Invalid JWT format. Expected 3 parts separated by dots.');
        }
        
        // Decode header
        const header = JSON.parse(base64UrlDecode(parts[0]));
        headerOutput.textContent = JSON.stringify(header, null, 2);
        
        // Decode payload
        const payload = JSON.parse(base64UrlDecode(parts[1]));
        payloadOutput.textContent = JSON.stringify(payload, null, 2);
        
        // Display signature (can't decode without secret)
        signatureOutput.textContent = parts[2];
        
        // Generate info about the token
        const info = generateTokenInfo(header, payload);
        infoOutput.innerHTML = info;
        
        // Show output container
        outputContainer.style.display = 'block';
        
        // Scroll to output
        outputContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
        
        showToast('JWT decoded successfully!', 'success');
    } catch (error) {
        showToast('Decoding failed: ' + error.message, 'error');
        outputContainer.style.display = 'none';
    }
}

// Base64 URL decode (JWT uses base64url encoding)
function base64UrlDecode(str) {
    // Replace URL-safe characters
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    
    // Add padding if needed
    while (str.length % 4) {
        str += '=';
    }
    
    // Decode base64
    try {
        return decodeURIComponent(atob(str).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
    } catch (e) {
        // Fallback for non-UTF8 content
        return atob(str);
    }
}

// Generate informative analysis about the token
function generateTokenInfo(header, payload) {
    let info = '<div class="jwt-analysis">';
    info += '<h3>🔍 Token Analysis</h3>';
    info += '<div class="analysis-grid">';
    
    // Algorithm
    const algorithm = header.alg || 'Unknown';
    const algClass = algorithm === 'none' ? 'warning' : 'info';
    info += `<div class="analysis-item ${algClass}">`;
    info += `<strong>Algorithm:</strong> ${algorithm}`;
    if (algorithm === 'none') {
        info += ' ⚠️ <span class="warning-text">No signature verification!</span>';
    }
    info += '</div>';
    
    // Token Type
    info += `<div class="analysis-item">`;
    info += `<strong>Type:</strong> ${header.typ || 'JWT'}`;
    info += '</div>';
    
    // Issued At
    if (payload.iat) {
        const iat = new Date(payload.iat * 1000);
        info += `<div class="analysis-item">`;
        info += `<strong>Issued:</strong> ${iat.toLocaleString()}`;
        info += '</div>';
    }
    
    // Expiration
    if (payload.exp) {
        const exp = new Date(payload.exp * 1000);
        const now = new Date();
        const expired = exp < now;
        const expClass = expired ? 'error' : 'success';
        info += `<div class="analysis-item ${expClass}">`;
        info += `<strong>Expires:</strong> ${exp.toLocaleString()}`;
        if (expired) {
            info += ' ❌ <span class="error-text">Expired</span>';
        } else {
            info += ' ✅ <span class="success-text">Valid</span>';
        }
        info += '</div>';
    }
    
    // Subject
    if (payload.sub) {
        info += `<div class="analysis-item">`;
        info += `<strong>Subject:</strong> ${payload.sub}`;
        info += '</div>';
    }
    
    // Audience
    if (payload.aud) {
        info += `<div class="analysis-item">`;
        info += `<strong>Audience:</strong> ${payload.aud}`;
        info += '</div>';
    }
    
    // Custom claims
    const standardClaims = ['iat', 'exp', 'sub', 'aud', 'iss', 'nbf', 'jti'];
    const customClaims = Object.keys(payload).filter(key => !standardClaims.includes(key));
    if (customClaims.length > 0) {
        info += `<div class="analysis-item info">`;
        info += `<strong>Custom Claims:</strong> ${customClaims.join(', ')}`;
        info += '</div>';
    }
    
    info += '</div>'; // Close analysis-grid
    
    // Security warnings
    info += '<div class="security-warnings">';
    info += '<h4>🛡️ Security Notes</h4>';
    info += '<ul>';
    
    if (algorithm === 'none') {
        info += '<li class="warning">⚠️ Algorithm set to "none" - signature not verified</li>';
    }
    
    if (algorithm === 'HS256') {
        info += '<li class="info">ℹ️ HMAC-SHA256 - try cracking the secret with jwt_tool or hashcat</li>';
    }
    
    if (header.kid) {
        info += '<li class="warning">⚠️ "kid" parameter present - test for path traversal or SQL injection</li>';
    }
    
    if (payload.admin || payload.role || payload.privileges) {
        info += '<li class="warning">⚠️ Authorization claims detected - try privilege escalation</li>';
    }
    
    if (!payload.exp) {
        info += '<li class="info">ℹ️ No expiration time - token may be valid indefinitely</li>';
    }
    
    info += '<li class="info">💡 Try modifying header algorithm (RS256→HS256) or payload claims</li>';
    info += '</ul>';
    info += '</div>';
    
    info += '</div>'; // Close jwt-analysis
    
    return info;
}

// Copy section functions
function copySection(section) {
    let text = '';
    
    if (section === 'header') {
        text = document.getElementById('jwt-header').textContent;
    } else if (section === 'payload') {
        text = document.getElementById('jwt-payload').textContent;
    } else if (section === 'signature') {
        text = document.getElementById('jwt-signature').textContent;
    }
    
    if (!text) {
        showToast('Nothing to copy!', 'error');
        return;
    }
    
    navigator.clipboard.writeText(text).then(() => {
        showToast(`${section.charAt(0).toUpperCase() + section.slice(1)} copied to clipboard!`, 'success');
    }).catch(() => {
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        showToast(`${section.charAt(0).toUpperCase() + section.slice(1)} copied to clipboard!`, 'success');
    });
}

// Clear all
function clearAll() {
    document.getElementById('jwt-input').value = '';
    document.getElementById('output-container').style.display = 'none';
}

// Toast notification function
function showToast(message, type = 'info') {
    // Remove existing toast if any
    const existingToast = document.querySelector('.toast');
    if (existingToast) {
        existingToast.remove();
    }
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    
    // Trigger animation
    setTimeout(() => toast.classList.add('show'), 10);
    
    // Remove after 3 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}
