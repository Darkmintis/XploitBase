// XOR Brute Force Tool

let inputFormat = 'text';

function setInputFormat(format) {
    inputFormat = format;
    
    // Update button states
    document.querySelectorAll('.format-btn[data-format]').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector(`.format-btn[data-format="${format}"]`).classList.add('active');
    
    // Update placeholder
    const placeholders = {
        text: 'Enter encrypted text...',
        hex: 'Enter hex (e.g., 1a2b3c4d)',
        base64: 'Enter base64 encoded data...'
    };
    document.getElementById('inputText').placeholder = placeholders[format];
}

function bruteForce() {
    const input = document.getElementById('inputText').value.trim();
    
    if (!input) {
        showToast('Please enter data to decrypt', 'error');
        return;
    }

    try {
        // Convert input to bytes based on format
        let bytes;
        
        switch(inputFormat) {
            case 'text':
                bytes = new TextEncoder().encode(input);
                break;
            case 'hex':
                bytes = hexToBytes(input);
                break;
            case 'base64':
                bytes = base64ToBytes(input);
                break;
            default:
                throw new Error('Invalid input format');
        }

        const showPrintable = document.getElementById('showPrintable').checked;
        const highlightEnglish = document.getElementById('highlightEnglish').checked;
        
        const resultsContainer = document.getElementById('resultsContainer');
        resultsContainer.innerHTML = '';
        
        let validResults = 0;

        // Try all 256 possible single-byte keys
        for (let key = 0; key <= 255; key++) {
            const decrypted = xorDecrypt(bytes, key);
            const isPrintable = checkPrintable(decrypted);
            
            // Skip non-printable if filter is enabled
            if (showPrintable && !isPrintable) {
                continue;
            }

            const text = bytesToText(decrypted);
            const isEnglish = highlightEnglish && checkEnglish(text);
            
            addResult(key, text, isEnglish);
            validResults++;
        }

        document.getElementById('resultCount').textContent = validResults;
        document.getElementById('resultsSection').style.display = 'block';
        
        if (validResults === 0) {
            resultsContainer.innerHTML = '<p class="no-results">No printable results found. Try unchecking "Show only printable results".</p>';
        } else {
            // Scroll to results
            document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
        
    } catch (error) {
        showToast(`Error: ${error.message}`, 'error');
    }
}

function xorDecrypt(bytes, key) {
    const result = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
        result[i] = bytes[i] ^ key;
    }
    return result;
}

function checkPrintable(bytes) {
    // Check if at least 80% of bytes are printable ASCII (32-126)
    let printableCount = 0;
    for (let byte of bytes) {
        if ((byte >= 32 && byte <= 126) || byte === 9 || byte === 10 || byte === 13) {
            printableCount++;
        }
    }
    return (printableCount / bytes.length) >= 0.8;
}

function checkEnglish(text) {
    // Simple heuristic: check for common English words and patterns
    const commonWords = ['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his', 'how', 'man', 'new', 'now', 'old', 'see', 'two', 'way', 'who', 'boy', 'did', 'its', 'let', 'put', 'say', 'she', 'too', 'use', 'flag', 'ctf', 'key'];
    const lowerText = text.toLowerCase();
    
    // Count matches
    let matches = 0;
    for (let word of commonWords) {
        if (lowerText.includes(word)) {
            matches++;
        }
    }
    
    // Also check for reasonable letter frequency
    const letters = text.replace(/[^a-zA-Z]/g, '').length;
    const ratio = letters / text.length;
    
    return matches >= 2 || ratio > 0.7;
}

function addResult(key, text, isHighlighted) {
    const resultsContainer = document.getElementById('resultsContainer');
    
    const resultItem = document.createElement('div');
    resultItem.className = `xor-result-item ${isHighlighted ? 'highlighted' : ''}`;
    resultItem.onclick = () => copyResult(text, key);
    
    const keyDiv = document.createElement('div');
    keyDiv.className = 'xor-key';
    
    // Format key display
    const keyChar = key >= 32 && key <= 126 ? ` (${String.fromCharCode(key)})` : '';
    const keyHex = key.toString(16).padStart(2, '0');
    
    if (isHighlighted) {
        keyDiv.innerHTML = `<i class="fas fa-star"></i> Key: ${key} (0x${keyHex})${keyChar} - Likely English!`;
    } else {
        keyDiv.innerHTML = `Key: ${key} (0x${keyHex})${keyChar}`;
    }
    
    const outputDiv = document.createElement('div');
    outputDiv.className = 'xor-output';
    outputDiv.textContent = text.substring(0, 200) + (text.length > 200 ? '...' : '');
    
    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-btn-small';
    copyBtn.innerHTML = '<i class="fas fa-copy"></i> Copy';
    copyBtn.onclick = (e) => {
        e.stopPropagation();
        copyResult(text, key);
    };
    
    resultItem.appendChild(keyDiv);
    resultItem.appendChild(outputDiv);
    resultItem.appendChild(copyBtn);
    
    resultsContainer.appendChild(resultItem);
}

function copyResult(text, key) {
    navigator.clipboard.writeText(text).then(() => {
        showToast(`Key ${key} result copied!`, 'success');
    }).catch(() => {
        showToast('Failed to copy', 'error');
    });
}

// Helper functions
function hexToBytes(hex) {
    const cleaned = hex.replace(/[^0-9a-fA-F]/g, '');
    if (cleaned.length % 2 !== 0) {
        throw new Error('Hex string must have even length');
    }
    const bytes = [];
    for (let i = 0; i < cleaned.length; i += 2) {
        bytes.push(parseInt(cleaned.substr(i, 2), 16));
    }
    return new Uint8Array(bytes);
}

function base64ToBytes(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function bytesToText(bytes) {
    try {
        return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    } catch {
        // Fallback for invalid UTF-8
        return Array.from(bytes).map(b => {
            if (b >= 32 && b <= 126) {
                return String.fromCharCode(b);
            }
            return '.';
        }).join('');
    }
}

function clearAll() {
    document.getElementById('inputText').value = '';
    document.getElementById('resultsContainer').innerHTML = '';
    document.getElementById('resultsSection').style.display = 'none';
}

function showToast(message, type = 'success') {
    const existingToast = document.querySelector('.toast');
    if (existingToast) {
        existingToast.remove();
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
        <span>${message}</span>
    `;
    
    document.body.appendChild(toast);
    
    setTimeout(() => toast.classList.add('show'), 100);
    
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}
