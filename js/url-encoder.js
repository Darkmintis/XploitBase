// Tab Switching
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const tabName = btn.dataset.tab;
        
        // Update active tab button
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        // Update active tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(`${tabName}-content`).classList.add('active');
    });
});

// URL Encoding Functions
function encodeURL() {
    const input = document.getElementById('encode-input').value.trim();
    const output = document.getElementById('encode-output');
    
    if (!input) {
        showToast('Please enter text or URL to encode', 'error');
        return;
    }
    
    try {
        const encodeComponents = document.getElementById('encode-components').checked;
        const doubleEncode = document.getElementById('double-encode').checked;
        
        let encoded;
        
        if (encodeComponents) {
            // Encode only URL components (query params, path segments)
            encoded = encodeURIComponent(input);
        } else {
            // Full URL encoding
            encoded = encodeURI(input);
        }
        
        // Double encode if requested (for filter bypass)
        if (doubleEncode) {
            encoded = encodeURIComponent(encoded);
        }
        
        output.value = encoded;
        showToast('URL encoded successfully!', 'success');
    } catch (error) {
        showToast('Encoding failed: ' + error.message, 'error');
        output.value = 'Error: Invalid input';
    }
}

function decodeURL() {
    const input = document.getElementById('decode-input').value.trim();
    const output = document.getElementById('decode-output');
    
    if (!input) {
        showToast('Please enter encoded URL to decode', 'error');
        return;
    }
    
    try {
        const recursiveDecode = document.getElementById('recursive-decode').checked;
        let decoded = input;
        let iterations = 0;
        const maxIterations = 10; // Prevent infinite loops
        
        if (recursiveDecode) {
            // Keep decoding until no more encoding is detected
            let previous = '';
            while (decoded !== previous && iterations < maxIterations) {
                previous = decoded;
                try {
                    decoded = decodeURIComponent(decoded);
                    iterations++;
                } catch (e) {
                    // If decoding fails, try decodeURI instead
                    try {
                        decoded = decodeURI(decoded);
                        iterations++;
                    } catch (e2) {
                        break; // Can't decode further
                    }
                }
            }
            
            if (iterations > 0) {
                output.value = decoded;
                showToast(`URL decoded successfully (${iterations} iteration${iterations > 1 ? 's' : ''})!`, 'success');
            } else {
                output.value = decoded;
                showToast('URL was not encoded or already decoded', 'info');
            }
        } else {
            // Single decode
            decoded = decodeURIComponent(decoded);
            output.value = decoded;
            showToast('URL decoded successfully!', 'success');
        }
    } catch (error) {
        // Fallback to decodeURI if decodeURIComponent fails
        try {
            const decoded = decodeURI(input);
            output.value = decoded;
            showToast('URL decoded successfully!', 'success');
        } catch (error2) {
            showToast('Decoding failed: ' + error2.message, 'error');
            output.value = 'Error: Invalid encoded URL';
        }
    }
}

// Clear Functions
function clearEncode() {
    document.getElementById('encode-input').value = '';
    document.getElementById('encode-output').value = '';
}

function clearDecode() {
    document.getElementById('decode-input').value = '';
    document.getElementById('decode-output').value = '';
}

// Copy Functions
function copyEncoded() {
    const output = document.getElementById('encode-output');
    if (!output.value) {
        showToast('Nothing to copy!', 'error');
        return;
    }
    
    navigator.clipboard.writeText(output.value).then(() => {
        showToast('Encoded URL copied to clipboard!', 'success');
    }).catch(() => {
        output.select();
        showToast('Encoded URL copied to clipboard!', 'success');
    });
}

function copyDecoded() {
    const output = document.getElementById('decode-output');
    if (!output.value) {
        showToast('Nothing to copy!', 'error');
        return;
    }
    
    navigator.clipboard.writeText(output.value).then(() => {
        showToast('Decoded URL copied to clipboard!', 'success');
    }).catch(() => {
        output.select();
        showToast('Decoded URL copied to clipboard!', 'success');
    });
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
