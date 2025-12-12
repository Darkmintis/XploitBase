// Hex/Binary Converter

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
        text: 'Enter text to convert...',
        hex: 'Enter hex (e.g., 48656c6c6f or 48 65 6c 6c 6f)',
        binary: 'Enter binary (e.g., 01001000 01100101)',
        decimal: 'Enter decimal bytes (e.g., 72 101 108)',
        octal: 'Enter octal bytes (e.g., 110 145 154)'
    };
    document.getElementById('inputText').placeholder = placeholders[format];
    
    // Auto-convert if there's input
    const input = document.getElementById('inputText').value.trim();
    if (input) {
        convert();
    }
}

function convert() {
    const input = document.getElementById('inputText').value.trim();
    
    if (!input) {
        showToast('Please enter data to convert', 'error');
        return;
    }

    try {
        // Convert input to byte array based on input format
        let bytes;
        
        switch(inputFormat) {
            case 'text':
                bytes = textToBytes(input);
                break;
            case 'hex':
                bytes = hexToBytes(input);
                break;
            case 'binary':
                bytes = binaryToBytes(input);
                break;
            case 'decimal':
                bytes = decimalToBytes(input);
                break;
            case 'octal':
                bytes = octalToBytes(input);
                break;
            default:
                throw new Error('Invalid input format');
        }

        // Generate output in selected formats
        const outputContainer = document.getElementById('outputContainer');
        outputContainer.innerHTML = '';
        
        if (document.getElementById('outText').checked) {
            addOutput('Text', bytesToText(bytes), 'font');
        }
        if (document.getElementById('outHex').checked) {
            addOutput('Hexadecimal', bytesToHex(bytes), 'hashtag');
        }
        if (document.getElementById('outBinary').checked) {
            addOutput('Binary', bytesToBinary(bytes), 'binary');
        }
        if (document.getElementById('outDecimal').checked) {
            addOutput('Decimal', bytesToDecimal(bytes), 'sort-numeric-up');
        }
        if (document.getElementById('outOctal').checked) {
            addOutput('Octal', bytesToOctal(bytes), 'circle');
        }

        document.getElementById('outputSection').style.display = 'block';
        
    } catch (error) {
        showToast(`Conversion error: ${error.message}`, 'error');
    }
}

// Conversion functions
function textToBytes(text) {
    return new TextEncoder().encode(text);
}

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

function binaryToBytes(binary) {
    const cleaned = binary.replace(/[^01]/g, '');
    if (cleaned.length % 8 !== 0) {
        throw new Error('Binary string length must be multiple of 8');
    }
    const bytes = [];
    for (let i = 0; i < cleaned.length; i += 8) {
        bytes.push(parseInt(cleaned.substr(i, 8), 2));
    }
    return new Uint8Array(bytes);
}

function decimalToBytes(decimal) {
    const numbers = decimal.match(/\d+/g);
    if (!numbers) {
        throw new Error('Invalid decimal format');
    }
    const bytes = numbers.map(n => {
        const num = parseInt(n, 10);
        if (num < 0 || num > 255) {
            throw new Error(`Decimal value ${num} out of range (0-255)`);
        }
        return num;
    });
    return new Uint8Array(bytes);
}

function octalToBytes(octal) {
    const numbers = octal.match(/[0-7]+/g);
    if (!numbers) {
        throw new Error('Invalid octal format');
    }
    const bytes = numbers.map(n => {
        const num = parseInt(n, 8);
        if (num < 0 || num > 255) {
            throw new Error(`Octal value ${n} out of range`);
        }
        return num;
    });
    return new Uint8Array(bytes);
}

function bytesToText(bytes) {
    return new TextDecoder().decode(bytes);
}

function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ');
}

function bytesToBinary(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(2).padStart(8, '0'))
        .join(' ');
}

function bytesToDecimal(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(10))
        .join(' ');
}

function bytesToOctal(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(8).padStart(3, '0'))
        .join(' ');
}

function addOutput(label, value, icon) {
    const outputContainer = document.getElementById('outputContainer');
    
    const outputCard = document.createElement('div');
    outputCard.className = 'output-field';
    
    const labelDiv = document.createElement('div');
    labelDiv.className = 'output-label';
    labelDiv.innerHTML = `<i class="fas fa-${icon}"></i> ${label}`;
    
    const valueDiv = document.createElement('div');
    valueDiv.className = 'output-value';
    valueDiv.textContent = value;
    
    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-btn';
    copyBtn.innerHTML = '<i class="fas fa-copy"></i> Copy';
    copyBtn.onclick = () => copyToClipboard(value, label);
    
    outputCard.appendChild(labelDiv);
    outputCard.appendChild(valueDiv);
    outputCard.appendChild(copyBtn);
    
    outputContainer.appendChild(outputCard);
}

function copyToClipboard(text, label) {
    navigator.clipboard.writeText(text).then(() => {
        showToast(`${label} copied to clipboard!`, 'success');
    }).catch(() => {
        showToast('Failed to copy', 'error');
    });
}

function clearAll() {
    document.getElementById('inputText').value = '';
    document.getElementById('outputContainer').innerHTML = '';
    document.getElementById('outputSection').style.display = 'none';
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

// Auto-convert on page load if there's example text
window.addEventListener('DOMContentLoaded', () => {
    const inputText = document.getElementById('inputText').value.trim();
    if (inputText) {
        convert();
    }
});

// Real-time conversion on input
document.addEventListener('DOMContentLoaded', () => {
    const inputField = document.getElementById('inputText');
    let timeout;
    inputField.addEventListener('input', () => {
        clearTimeout(timeout);
        timeout = setTimeout(() => {
            if (inputField.value.trim()) {
                convert();
            }
        }, 500);
    });
});
