// ROT/Caesar Cipher Decoder

function rotateLetter(char, shift) {
    const code = char.charCodeAt(0);
    
    // Uppercase letters (A-Z)
    if (code >= 65 && code <= 90) {
        return String.fromCharCode(((code - 65 + shift) % 26) + 65);
    }
    // Lowercase letters (a-z)
    if (code >= 97 && code <= 122) {
        return String.fromCharCode(((code - 97 + shift) % 26) + 97);
    }
    // Non-alphabetic characters remain unchanged
    return char;
}

function rotateText(text, shift) {
    return text.split('').map(char => rotateLetter(char, shift)).join('');
}

function decodeAll() {
    const inputText = document.getElementById('inputText').value.trim();
    
    if (!inputText) {
        showToast('Please enter text to decode', 'error');
        return;
    }

    const resultsContainer = document.getElementById('resultsContainer');
    const resultsSection = document.getElementById('resultsSection');
    
    resultsContainer.innerHTML = '';
    resultsSection.style.display = 'block';

    // Generate all 26 rotations
    for (let i = 0; i < 26; i++) {
        const rotated = rotateText(inputText, i);
        const resultCard = createResultCard(i, rotated);
        resultsContainer.appendChild(resultCard);
    }

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function createResultCard(rotation, text) {
    const card = document.createElement('div');
    card.className = 'result-card';
    card.onclick = () => copyResult(text, rotation);
    
    const header = document.createElement('div');
    header.className = 'result-header';
    
    const rotLabel = document.createElement('span');
    rotLabel.className = 'rotation-label';
    
    // Highlight special rotations
    if (rotation === 13) {
        rotLabel.innerHTML = `<i class="fas fa-star"></i> ROT${rotation} (Most Common)`;
        rotLabel.style.color = '#00ff88';
    } else if (rotation === 3) {
        rotLabel.innerHTML = `<i class="fas fa-crown"></i> ROT${rotation} (Caesar)`;
        rotLabel.style.color = '#ffd700';
    } else {
        rotLabel.innerHTML = `ROT${rotation}`;
    }
    
    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-btn-small';
    copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
    copyBtn.onclick = (e) => {
        e.stopPropagation();
        copyResult(text, rotation);
    };
    
    header.appendChild(rotLabel);
    header.appendChild(copyBtn);
    
    const resultText = document.createElement('div');
    resultText.className = 'result-text';
    resultText.textContent = text;
    
    card.appendChild(header);
    card.appendChild(resultText);
    
    return card;
}

function copyResult(text, rotation) {
    navigator.clipboard.writeText(text).then(() => {
        showToast(`ROT${rotation} copied to clipboard!`, 'success');
    }).catch(() => {
        showToast('Failed to copy', 'error');
    });
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

// Auto-decode on page load if there's example text
globalThis.addEventListener('DOMContentLoaded', () => {
    const inputText = document.getElementById('inputText').value.trim();
    if (inputText) {
        decodeAll();
    }
});
