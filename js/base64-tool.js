// Base64 Encoder/Decoder Tool

document.addEventListener('DOMContentLoaded', function() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    const encodeInput = document.getElementById('encodeInput');
    const encodeOutput = document.getElementById('encodeOutput');
    const encodeBtn = document.getElementById('encodeBtn');
    const clearEncodeBtn = document.getElementById('clearEncodeBtn');
    const copyEncodeBtn = document.getElementById('copyEncodeBtn');
    
    const decodeInput = document.getElementById('decodeInput');
    const decodeOutput = document.getElementById('decodeOutput');
    const decodeBtn = document.getElementById('decodeBtn');
    const clearDecodeBtn = document.getElementById('clearDecodeBtn');
    const copyDecodeBtn = document.getElementById('copyDecodeBtn');
    
    // Tab switching
    tabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const tabName = this.dataset.tab;
            
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            this.classList.add('active');
            document.getElementById(tabName).classList.add('active');
        });
    });
    
    // Encode functionality
    encodeBtn.addEventListener('click', encodeToBase64);
    encodeInput.addEventListener('keypress', function(e) {
        if (e.ctrlKey && e.key === 'Enter') {
            encodeToBase64();
        }
    });
    
    clearEncodeBtn.addEventListener('click', function() {
        encodeInput.value = '';
        encodeOutput.value = '';
    });
    
    copyEncodeBtn.addEventListener('click', function() {
        if (encodeOutput.value) {
            copyToClipboard(encodeOutput.value);
        } else {
            showToast('No output to copy');
        }
    });
    
    // Decode functionality
    decodeBtn.addEventListener('click', decodeFromBase64);
    decodeInput.addEventListener('keypress', function(e) {
        if (e.ctrlKey && e.key === 'Enter') {
            decodeFromBase64();
        }
    });
    
    clearDecodeBtn.addEventListener('click', function() {
        decodeInput.value = '';
        decodeOutput.value = '';
    });
    
    copyDecodeBtn.addEventListener('click', function() {
        if (decodeOutput.value) {
            copyToClipboard(decodeOutput.value);
        } else {
            showToast('No output to copy');
        }
    });
    
    function encodeToBase64() {
        const text = encodeInput.value;
        if (!text) {
            showToast('Please enter text to encode');
            return;
        }
        
        try {
            const encoded = btoa(unescape(encodeURIComponent(text)));
            encodeOutput.value = encoded;
            showToast('Text encoded successfully');
        } catch (error) {
            showToast('Error encoding text: ' + error.message);
            console.error('Encode error:', error);
        }
    }
    
    function decodeFromBase64() {
        const text = decodeInput.value.trim();
        if (!text) {
            showToast('Please enter Base64 to decode');
            return;
        }
        
        try {
            const decoded = decodeURIComponent(escape(atob(text)));
            decodeOutput.value = decoded;
            showToast('Base64 decoded successfully');
        } catch (error) {
            showToast('Error decoding Base64: Invalid input');
            console.error('Decode error:', error);
        }
    }
    
    function copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            showToast('Copied to clipboard!');
        }).catch(err => {
            console.error('Failed to copy:', err);
            showToast('Failed to copy to clipboard');
        });
    }
    
    function showToast(message) {
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.textContent = message;
        toast.style.cssText = `
            position: fixed;
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%);
            background-color: var(--accent-color);
            color: #fff;
            padding: 12px 24px;
            border-radius: 6px;
            z-index: 10000;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        `;
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 2000);
    }
});
