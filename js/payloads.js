// Payload Library JavaScript

let currentFilter = 'all';
let searchQuery = '';

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    renderPayloads();
    setupEventListeners();
    updatePayloadCount();
});

// Setup event listeners
function setupEventListeners() {
    // Filter buttons
    const filterBtns = document.querySelectorAll('.filter-btn');
    filterBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            // Update active state
            filterBtns.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            
            // Update filter and render
            currentFilter = this.dataset.category;
            renderPayloads();
        });
    });
    
    // Search input
    const searchInput = document.getElementById('payloadSearch');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            searchQuery = this.value.toLowerCase();
            renderPayloads();
        });
    }
}

// Filter payloads based on category and search query
function getFilteredPayloads() {
    let filtered = payloadLibrary;
    
    // Apply category filter
    if (currentFilter !== 'all') {
        filtered = filtered.filter(payload => payload.category === currentFilter);
    }
    
    // Apply search filter
    if (searchQuery) {
        filtered = filtered.filter(payload => {
            return payload.title.toLowerCase().includes(searchQuery) ||
                   payload.description.toLowerCase().includes(searchQuery) ||
                   payload.payload.toLowerCase().includes(searchQuery) ||
                   payload.tags.some(tag => tag.toLowerCase().includes(searchQuery));
        });
    }
    
    return filtered;
}

// Render payloads to the grid
function renderPayloads() {
    const grid = document.getElementById('payloadsGrid');
    const filtered = getFilteredPayloads();
    
    if (filtered.length === 0) {
        grid.innerHTML = `
            <div class="no-results">
                <i class="fas fa-search"></i>
                <h3>No payloads found</h3>
                <p>Try adjusting your filters or search query</p>
            </div>
        `;
        updatePayloadCount();
        return;
    }
    
    grid.innerHTML = filtered.map(payload => `
        <div class="payload-card" data-id="${payload.id}">
            <div class="payload-header">
                <h3 class="payload-title">${payload.title}</h3>
                <span class="payload-category ${payload.category}">${getCategoryName(payload.category)}</span>
            </div>
            
            <p class="payload-description">${payload.description}</p>
            
            <div class="payload-difficulty ${payload.difficulty}">
                <i class="fas fa-circle"></i> ${payload.difficulty.charAt(0).toUpperCase() + payload.difficulty.slice(1)}
            </div>
            
            <div class="payload-code">
                <pre>${escapeHtml(payload.payload)}</pre>
            </div>
            
            <div class="payload-actions">
                <button class="payload-copy-btn" onclick="copyPayload(${payload.id})">
                    <i class="fas fa-copy"></i> Copy Payload
                </button>
            </div>
            
            <div class="payload-tags">
                ${payload.tags.map(tag => `<span class="payload-tag">${tag}</span>`).join('')}
            </div>
        </div>
    `).join('');
    
    updatePayloadCount();
}

// Get category display name
function getCategoryName(category) {
    const names = {
        'xss': 'XSS',
        'sqli': 'SQL Injection',
        'ssti': 'SSTI',
        'lfi': 'LFI/RFI',
        'cmdi': 'Command Injection',
        'xxe': 'XXE',
        'ssrf': 'SSRF',
        'bypass': 'WAF Bypass'
    };
    return names[category] || category.toUpperCase();
}

// Copy payload to clipboard
function copyPayload(id) {
    const payload = payloadLibrary.find(p => p.id === id);
    if (!payload) return;
    
    const btn = document.querySelector(`[data-id="${id}"] .payload-copy-btn`);
    const originalHTML = btn.innerHTML;
    
    // Copy to clipboard
    navigator.clipboard.writeText(payload.payload).then(() => {
        // Success feedback
        btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
        btn.classList.add('copied');
        
        // Reset after 2 seconds
        setTimeout(() => {
            btn.innerHTML = originalHTML;
            btn.classList.remove('copied');
        }, 2000);
        
        showToast('Payload copied to clipboard!', 'success');
    }).catch(err => {
        // Fallback using legacy method
        const textarea = document.createElement('textarea');
        textarea.value = payload.payload;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
        } catch (e) {
            console.error('Copy failed:', e);
        }
        textarea.remove();
        
        btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
        btn.classList.add('copied');
        
        setTimeout(() => {
            btn.innerHTML = originalHTML;
            btn.classList.remove('copied');
        }, 2000);
        
        showToast('Payload copied to clipboard!', 'success');
    });
}

// Update payload count display
function updatePayloadCount() {
    const countElement = document.getElementById('payloadCount');
    const filtered = getFilteredPayloads();
    const total = payloadLibrary.length;
    
    if (countElement) {
        if (currentFilter === 'all' && !searchQuery) {
            countElement.textContent = `Showing all ${total} payloads`;
        } else {
            countElement.textContent = `Showing ${filtered.length} of ${total} payloads`;
        }
    }
}

// Escape HTML to prevent XSS in payload display
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Toast notification
function showToast(message, type = 'info') {
    const existingToast = document.querySelector('.toast');
    if (existingToast) {
        existingToast.remove();
    }
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    
    setTimeout(() => toast.classList.add('show'), 10);
    
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}
