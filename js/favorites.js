// Favorites and History Management for XploitBase

document.addEventListener('DOMContentLoaded', function() {
    // Initialize favorites and history
    window.XploitBaseFavorites = {
        add: function(command, toolName, category) {
            const favorites = this.getAll();
            const favorite = {
                id: Date.now().toString(),
                command: command,
                toolName: toolName,
                category: category,
                addedAt: new Date().toISOString()
            };
            
            // Check if already exists
            const exists = favorites.some(fav => fav.command === command);
            if (!exists) {
                favorites.push(favorite);
                localStorage.setItem('xploitbase_favorites', JSON.stringify(favorites));
                showToast('Added to favorites!');
                this.updateFavoritesPanel();
            } else {
                showToast('Already in favorites!');
            }
        },
        
        remove: function(id) {
            let favorites = this.getAll();
            favorites = favorites.filter(fav => fav.id !== id);
            localStorage.setItem('xploitbase_favorites', JSON.stringify(favorites));
            showToast('Removed from favorites');
            this.updateFavoritesPanel();
        },
        
        getAll: function() {
            return JSON.parse(localStorage.getItem('xploitbase_favorites') || '[]');
        },
        
        updateFavoritesPanel: function() {
            const panel = document.getElementById('favoritesPanel');
            if (panel) {
                const content = panel.querySelector('.panel-content');
                this.renderFavorites(content);
            }
        }
    };
    
    window.XploitBaseHistory = {
        add: function(command, toolName, category) {
            const history = this.getAll();
            const entry = {
                id: Date.now().toString(),
                command: command,
                toolName: toolName,
                category: category,
                usedAt: new Date().toISOString()
            };
            
            history.unshift(entry);
            
            // Keep only last 100 entries
            const trimmedHistory = history.slice(0, 100);
            localStorage.setItem('xploitbase_history', JSON.stringify(trimmedHistory));
            this.updateHistoryPanel();
        },
        
        clear: function() {
            if (confirm('Clear all command history?')) {
                localStorage.setItem('xploitbase_history', '[]');
                showToast('History cleared');
                this.updateHistoryPanel();
            }
        },
        
        getAll: function() {
            return JSON.parse(localStorage.getItem('xploitbase_history') || '[]');
        },
        
        updateHistoryPanel: function() {
            const panel = document.getElementById('favoritesPanel');
            if (panel) {
                const content = panel.querySelector('.panel-content');
                this.renderHistory(content);
            }
        }
    };
    
    // Create favorites panel
    window.createFavoritesPanel = function() {
        const panel = document.createElement('div');
        panel.id = 'favoritesPanel';
        panel.className = 'side-panel';
        panel.innerHTML = `
            <div class="panel-header">
                <h3><i class="fas fa-star"></i> Favorites & History</h3>
                <button class="panel-close" onclick="document.getElementById('favoritesPanel').classList.remove('active')">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="panel-tabs">
                <button class="panel-tab active" data-tab="favorites">
                    <i class="fas fa-star"></i> Favorites
                </button>
                <button class="panel-tab" data-tab="history">
                    <i class="fas fa-history"></i> History
                </button>
            </div>
            <div class="panel-content"></div>
        `;
        document.body.appendChild(panel);
        
        // Tab switching
        const tabs = panel.querySelectorAll('.panel-tab');
        tabs.forEach(tab => {
            tab.addEventListener('click', function() {
                tabs.forEach(t => t.classList.remove('active'));
                this.classList.add('active');
                
                const tabName = this.getAttribute('data-tab');
                const content = panel.querySelector('.panel-content');
                
                if (tabName === 'favorites') {
                    XploitBaseFavorites.renderFavorites(content);
                } else {
                    XploitBaseHistory.renderHistory(content);
                }
            });
        });
        
        // Show favorites by default
        XploitBaseFavorites.renderFavorites(panel.querySelector('.panel-content'));
    };
    
    XploitBaseFavorites.renderFavorites = function(container) {
        const favorites = this.getAll();
        
        if (favorites.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-star"></i>
                    <p>No favorites yet</p>
                    <small>Click the star icon on any command to add it</small>
                </div>
            `;
            return;
        }
        
        let html = '<div class="favorites-list">';
        favorites.forEach(fav => {
            html += `
                <div class="favorite-item">
                    <div class="favorite-header">
                        <span class="favorite-tool">${fav.toolName}</span>
                        <span class="favorite-category">${fav.category}</span>
                    </div>
                    <div class="favorite-command">
                        <code>${fav.command}</code>
                        <div class="favorite-actions">
                            <button class="fav-copy" data-command="${fav.command.replace(/"/g, '&quot;')}" title="Copy">
                                <i class="fas fa-copy"></i>
                            </button>
                            <button class="fav-remove" data-id="${fav.id}" title="Remove">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </div>
                </div>
            `;
        });
        html += '</div>';
        
        container.innerHTML = html;
        
        // Add event listeners
        container.querySelectorAll('.fav-copy').forEach(btn => {
            btn.addEventListener('click', function() {
                const cmd = this.getAttribute('data-command');
                navigator.clipboard.writeText(cmd);
                showToast('Copied to clipboard!');
            });
        });
        
        container.querySelectorAll('.fav-remove').forEach(btn => {
            btn.addEventListener('click', function() {
                const id = this.getAttribute('data-id');
                XploitBaseFavorites.remove(id);
            });
        });
    };
    
    XploitBaseHistory.renderHistory = function(container) {
        const history = this.getAll();
        
        if (history.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-history"></i>
                    <p>No command history</p>
                    <small>Commands you copy will appear here</small>
                </div>
            `;
            return;
        }
        
        let html = `
            <div class="history-header">
                <button class="clear-history-btn" id="clearHistoryBtn">
                    <i class="fas fa-trash"></i> Clear History
                </button>
            </div>
            <div class="history-list">
        `;
        
        history.forEach(entry => {
            const date = new Date(entry.usedAt);
            const timeAgo = getTimeAgo(date);
            
            html += `
                <div class="history-item">
                    <div class="history-header">
                        <span class="history-tool">${entry.toolName}</span>
                        <span class="history-time">${timeAgo}</span>
                    </div>
                    <div class="history-command">
                        <code>${entry.command}</code>
                        <button class="history-copy" data-command="${entry.command.replace(/"/g, '&quot;')}" title="Copy">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>
            `;
        });
        
        html += '</div>';
        container.innerHTML = html;
        
        // Add event listeners
        const clearBtn = container.querySelector('#clearHistoryBtn');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => XploitBaseHistory.clear());
        }
        
        container.querySelectorAll('.history-copy').forEach(btn => {
            btn.addEventListener('click', function() {
                const cmd = this.getAttribute('data-command');
                navigator.clipboard.writeText(cmd);
                showToast('Copied to clipboard!');
            });
        });
    };
    
    function getTimeAgo(date) {
        const seconds = Math.floor((new Date() - date) / 1000);
        
        if (seconds < 60) return 'just now';
        if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
        if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
        if (seconds < 604800) return Math.floor(seconds / 86400) + 'd ago';
        return date.toLocaleDateString();
    }
});
