// Flag Format Converter - Smart flag format conversion for CTFs

document.addEventListener('DOMContentLoaded', function() {
    const inputText = document.getElementById('inputText');
    const convertBtn = document.getElementById('convertBtn');
    const outputSection = document.getElementById('outputSection');
    const resultsContainer = document.getElementById('resultsContainer');
    const formatBtns = document.querySelectorAll('.format-btn');
    const autoDetect = document.getElementById('autoDetect');
    const smartSplit = document.getElementById('smartSplit');
    const customFormatInput = document.getElementById('customFormatInput');
    const customFormat = document.getElementById('customFormat');
    
    let selectedFormat = 'CTF'; // Default format
    
    // Format selection
    formatBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            formatBtns.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            selectedFormat = this.dataset.format;
            
            if (selectedFormat === 'custom') {
                customFormatInput.style.display = 'block';
            } else {
                customFormatInput.style.display = 'none';
            }
        });
    });
    
    // Convert button
    convertBtn.addEventListener('click', convertFlag);
    
    // Enter key in input
    inputText.addEventListener('keypress', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            convertFlag();
        }
    });
    
    // Try example buttons
    document.querySelectorAll('.try-example-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const card = this.closest('.example-card');
            const example = card.dataset.example;
            const format = card.dataset.format;
            
            inputText.value = example;
            formatBtns.forEach(b => b.classList.remove('active'));
            const formatBtn = Array.from(formatBtns).find(b => b.dataset.format === format);
            if (formatBtn) {
                formatBtn.classList.add('active');
                selectedFormat = format;
            }
            
            convertFlag();
            inputText.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
    });
    
    function convertFlag() {
        const text = inputText.value.trim();
        if (!text) {
            showToast('Please enter some text to convert');
            return;
        }
        
        const format = selectedFormat === 'custom' ? customFormat.value.trim().toUpperCase() : selectedFormat;
        if (!format) {
            showToast('Please enter a custom format');
            return;
        }
        
        const results = generateFlagVariations(text, format);
        displayResults(results);
    }
    
    function generateFlagVariations(text, format) {
        const results = [];
        let cleanText = text.trim();
        
        // Auto-detect and remove existing flag format
        if (autoDetect.checked) {
            const flagPrefixes = ['HTB', 'CTF', 'FLAG', 'picoCTF', 'flag'];
            for (const prefix of flagPrefixes) {
                const regex = new RegExp(`^${prefix}[{]?`, 'i');
                cleanText = cleanText.replace(regex, '');
                cleanText = cleanText.replace(/[{}]/g, '');
            }
        }
        
        // Generate variations
        if (smartSplit.checked) {
            // Smart word splitting variations
            const words = smartWordSplit(cleanText);
            
            // Variation 1: UPPERCASE with underscores
            results.push({
                name: 'Uppercase with underscores',
                flag: `${format}{${words.map(w => w.toUpperCase()).join('_')}}`,
                description: 'Standard uppercase format'
            });
            
            // Variation 2: lowercase with underscores
            results.push({
                name: 'Lowercase with underscores',
                flag: `${format.toLowerCase()}{${words.map(w => w.toLowerCase()).join('_')}}`,
                description: 'All lowercase variant'
            });
            
            // Variation 3: Mixed case with underscores
            results.push({
                name: 'Mixed case with underscores',
                flag: `${format}{${words.join('_')}}`,
                description: 'Preserves original casing'
            });
            
            // Variation 4: UPPERCASE without underscores
            results.push({
                name: 'Uppercase no separators',
                flag: `${format}{${words.map(w => w.toUpperCase()).join('')}}`,
                description: 'Concatenated uppercase'
            });
            
            // Variation 5: lowercase without underscores
            results.push({
                name: 'Lowercase no separators',
                flag: `${format.toLowerCase()}{${words.map(w => w.toLowerCase()).join('')}}`,
                description: 'Concatenated lowercase'
            });
            
            // Variation 6: With hyphens
            results.push({
                name: 'Lowercase with hyphens',
                flag: `${format.toLowerCase()}{${words.map(w => w.toLowerCase()).join('-')}}`,
                description: 'Hyphen separated'
            });
        } else {
            // Simple variations without splitting
            results.push({
                name: 'Uppercase',
                flag: `${format}{${cleanText.toUpperCase()}}`,
                description: 'Simple uppercase'
            });
            
            results.push({
                name: 'Lowercase',
                flag: `${format.toLowerCase()}{${cleanText.toLowerCase()}}`,
                description: 'Simple lowercase'
            });
            
            results.push({
                name: 'Original case',
                flag: `${format}{${cleanText}}`,
                description: 'Preserves input casing'
            });
        }
        
        return results;
    }
    
    function smartWordSplit(text) {
        // Remove any existing separators
        text = text.replace(/[_\-\s]+/g, '');
        
        // Split on capital letters (camelCase)
        let words = text.split(/(?=[A-Z])/);
        
        // Further split on numbers
        words = words.flatMap(word => word.split(/(?=\d)|(?<=\d)(?=[a-zA-Z])/));
        
        // Clean up empty strings
        words = words.filter(w => w.length > 0);
        
        // If no splits were made, try to split by common patterns
        if (words.length === 1) {
            // Try to split by common word patterns
            const commonWords = ['admin', 'user', 'password', 'login', 'test', 'flag', 'ctf', 'web', 'app'];
            let found = false;
            
            for (const common of commonWords) {
                const regex = new RegExp(`(${common})`, 'i');
                if (regex.test(text.toLowerCase())) {
                    words = text.toLowerCase().split(regex).filter(w => w.length > 0);
                    found = true;
                    break;
                }
            }
            
            // If still no splits, split every 3-4 characters as a fallback
            if (!found && text.length > 6) {
                words = text.match(/.{1,4}/g) || [text];
            }
        }
        
        return words;
    }
    
    function displayResults(results) {
        outputSection.style.display = 'block';
        resultsContainer.innerHTML = '';
        
        results.forEach((result, index) => {
            const resultCard = document.createElement('div');
            resultCard.className = 'result-card-flag';
            resultCard.innerHTML = `
                <div class="result-header-flag">
                    <h4>${result.name}</h4>
                    <span class="result-desc">${result.description}</span>
                </div>
                <div class="flag-display">
                    <code>${result.flag}</code>
                    <button class="copy-flag-btn" data-flag="${result.flag}" title="Copy to clipboard">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
            `;
            
            resultsContainer.appendChild(resultCard);
        });
        
        // Add copy event listeners
        document.querySelectorAll('.copy-flag-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const flag = this.dataset.flag;
                copyToClipboard(flag);
                this.innerHTML = '<i class="fas fa-check"></i>';
                setTimeout(() => {
                    this.innerHTML = '<i class="fas fa-copy"></i>';
                }, 2000);
            });
        });
        
        // Scroll to results
        outputSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
    
    function copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            showToast('Flag copied to clipboard!');
        }).catch(err => {
            console.error('Failed to copy:', err);
            showToast('Failed to copy flag');
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
