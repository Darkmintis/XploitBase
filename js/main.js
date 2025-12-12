// Main JavaScript for XploitBase

document.addEventListener('DOMContentLoaded', function() {
    const mainSearchInput = document.getElementById('mainSearchInput');
    const searchResults = document.getElementById('searchResults');
    const searchStats = document.getElementById('searchStats');
    const themeToggleBtn = document.getElementById('themeToggle');
    
    let searchIndex = [];
    let recentSearches = JSON.parse(localStorage.getItem('recentSearches')) || [];
    
    // Build search index from all categories
    buildSearchIndex();
    
    // Theme Toggle functionality
    const currentTheme = localStorage.getItem('theme') || 'dark';
    if (currentTheme === 'light') {
        document.body.classList.add('light-theme');
        themeToggleBtn.innerHTML = '<i class="fas fa-sun"></i>';
    } else {
        document.body.classList.remove('light-theme');
        themeToggleBtn.innerHTML = '<i class="fas fa-moon"></i>';
    }
    
    // Handle theme toggle click
    themeToggleBtn.addEventListener('click', function() {
        document.body.classList.toggle('light-theme');
        
        if (document.body.classList.contains('light-theme')) {
            localStorage.setItem('theme', 'light');
            themeToggleBtn.innerHTML = '<i class="fas fa-sun"></i>';
        } else {
            localStorage.setItem('theme', 'dark');
            themeToggleBtn.innerHTML = '<i class="fas fa-moon"></i>';
        }
    });
    
    // Real-time search
    if (mainSearchInput) {
        mainSearchInput.addEventListener('input', function() {
            const query = this.value.trim();
            if (query.length >= 2) {
                performInstantSearch(query);
            } else {
                clearSearchResults();
            }
        });
        
        mainSearchInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                const query = this.value.trim();
                if (query) {
                    addToRecentSearches(query);
                    performInstantSearch(query);
                }
            }
        });
    }
    
    // Handle popular search tags
    document.querySelectorAll('.search-tag').forEach(tag => {
        tag.addEventListener('click', function() {
            const searchTerm = this.dataset.search;
            if (mainSearchInput) {
                mainSearchInput.value = searchTerm;
                addToRecentSearches(searchTerm);
                performInstantSearch(searchTerm);
                mainSearchInput.focus();
            }
        });
    });
    
    // Handle modal close (for compatibility)
    const closeBtn = document.querySelector('.close');
    if(closeBtn) {
        closeBtn.addEventListener('click', function() {
            modal.style.display = 'none';
        });
    }
    
    // Close modal when clicking outside
    globalThis.addEventListener('click', function(event) {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
    
    // Functions
    function navigateToCategory(categoryId) {
        const category = xploitBaseData.categories.find(cat => cat.id === categoryId);
        
        if (category) {
            // Get main content container
            const mainContent = document.querySelector('main .container');
            mainContent.innerHTML = '';
            
            // Add back button
            const backBtn = document.createElement('a');
            backBtn.href = 'index.html';
            backBtn.className = 'back-btn';
            backBtn.innerHTML = '<i class="fas fa-arrow-left"></i> Back to Categories';
            mainContent.appendChild(backBtn);
            
            // Add category title
            const categoryTitle = document.createElement('h2');
            categoryTitle.textContent = category.name + ' Tools';
            categoryTitle.style.marginBottom = '30px';
            mainContent.appendChild(categoryTitle);
            
            // Create tools list
            const toolsSection = document.createElement('section');
            toolsSection.className = 'tools-list';
            
            category.tools.forEach(tool => {
                const toolCard = document.createElement('div');
                toolCard.className = 'tool-card';
                
                const toolHeader = document.createElement('h3');
                toolHeader.innerHTML = tool.name;
                
                const toolDesc = document.createElement('div');
                toolDesc.className = 'description';
                toolDesc.textContent = tool.description;
                
                const commandsTitle = document.createElement('h4');
                commandsTitle.textContent = 'Commands:';
                
                const commandsList = document.createElement('div');
                commandsList.className = 'commands';
                
                tool.commands.forEach(cmd => {
                    const commandItem = document.createElement('div');
                    commandItem.className = 'command-item';
                    
                    const commandText = document.createElement('div');
                    commandText.className = 'command-text';
                    commandText.textContent = cmd.command;
                    
                    const commandButtons = document.createElement('div');
                    commandButtons.className = 'command-buttons';
                    
                    const copyBtn = document.createElement('button');
                    copyBtn.className = 'copy-btn';
                    copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
                    copyBtn.title = 'Copy to clipboard';
                    copyBtn.addEventListener('click', function() {
                        copyToClipboard(cmd.command);
                    });
                    
                    const learnBtn = document.createElement('button');
                    learnBtn.className = 'learn-btn';
                    learnBtn.innerHTML = '<i class="fas fa-info-circle"></i>';
                    learnBtn.title = 'Learn more';
                    learnBtn.addEventListener('click', function() {
                        showLearnModal(cmd);
                    });
                    
                    commandButtons.appendChild(copyBtn);
                    commandButtons.appendChild(learnBtn);
                    
                    commandItem.appendChild(commandText);
                    commandItem.appendChild(commandButtons);
                    
                    if (cmd.description) {
                        const commandDesc = document.createElement('div');
                        commandDesc.className = 'command-description';
                        commandDesc.textContent = cmd.description;
                        commandItem.appendChild(commandDesc);
                    }
                    
                    commandsList.appendChild(commandItem);
                });
                
                toolCard.appendChild(toolHeader);
                toolCard.appendChild(toolDesc);
                toolCard.appendChild(commandsTitle);
                toolCard.appendChild(commandsList);
                
                toolsSection.appendChild(toolCard);
            });
            
            mainContent.appendChild(toolsSection);
            
            // Update page title
            document.title = category.name + ' Tools - XploitBase';
        }
    }
    
    function performSearch() {
        const searchTerm = searchInput.value.toLowerCase().trim();
        if (searchTerm === '') return;
        
        // Get main content container
        const mainContent = document.querySelector('main .container');
        mainContent.innerHTML = '';
        
        // Add back button
        const backBtn = document.createElement('a');
        backBtn.href = 'index.html';
        backBtn.className = 'back-btn';
        backBtn.innerHTML = '<i class="fas fa-arrow-left"></i> Back to Categories';
        mainContent.appendChild(backBtn);
        
        // Add search results title
        const searchTitle = document.createElement('h2');
        searchTitle.textContent = `Search Results for "${searchTerm}"`;
        searchTitle.style.marginBottom = '30px';
        mainContent.appendChild(searchTitle);
        
        // Create results section
        const resultsSection = document.createElement('section');
        resultsSection.className = 'search-results';
        
        let resultsFound = false;
        
        // Search through all tools and commands
        xploitBaseData.categories.forEach(category => {
            category.tools.forEach(tool => {
                // Search in tool name and description
                const toolMatches = 
                    tool.name.toLowerCase().includes(searchTerm) || 
                    tool.description.toLowerCase().includes(searchTerm);
                
                // Search in commands
                const commandMatches = tool.commands.filter(cmd => 
                    cmd.name.toLowerCase().includes(searchTerm) || 
                    cmd.command.toLowerCase().includes(searchTerm) || 
                    cmd.description?.toLowerCase().includes(searchTerm)
                );
                
                if (toolMatches || commandMatches.length > 0) {
                    resultsFound = true;
                    
                    const toolCard = document.createElement('div');
                    toolCard.className = 'tool-card';
                    
                    const toolHeader = document.createElement('h3');
                    toolHeader.innerHTML = `${tool.name} <span style="color: var(--text-secondary); font-size: 0.8rem;">(${category.name})</span>`;
                    
                    const toolDesc = document.createElement('div');
                    toolDesc.className = 'description';
                    toolDesc.textContent = tool.description;
                    
                    toolCard.appendChild(toolHeader);
                    toolCard.appendChild(toolDesc);
                    
                    if (commandMatches.length > 0) {
                        const commandsTitle = document.createElement('h4');
                        commandsTitle.textContent = 'Matching Commands:';
                        toolCard.appendChild(commandsTitle);
                        
                        const commandsList = document.createElement('div');
                        commandsList.className = 'commands';
                        
                        commandMatches.forEach(cmd => {
                            const commandItem = document.createElement('div');
                            commandItem.className = 'command-item';
                            
                            const commandText = document.createElement('div');
                            commandText.className = 'command-text';
                            commandText.textContent = cmd.command;
                            
                            const commandButtons = document.createElement('div');
                            commandButtons.className = 'command-buttons';
                            
                            const copyBtn = document.createElement('button');
                            copyBtn.className = 'copy-btn';
                            copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
                            copyBtn.title = 'Copy to clipboard';
                            copyBtn.addEventListener('click', function() {
                                copyToClipboard(cmd.command);
                            });
                            
                            const learnBtn = document.createElement('button');
                            learnBtn.className = 'learn-btn';
                            learnBtn.innerHTML = '<i class="fas fa-info-circle"></i>';
                            learnBtn.title = 'Learn more';
                            learnBtn.addEventListener('click', function() {
                                showLearnModal(cmd);
                            });
                            
                            commandButtons.appendChild(copyBtn);
                            commandButtons.appendChild(learnBtn);
                            
                            commandItem.appendChild(commandText);
                            commandItem.appendChild(commandButtons);
                            
                            if (cmd.description) {
                                const commandDesc = document.createElement('div');
                                commandDesc.className = 'command-description';
                                commandDesc.textContent = cmd.description;
                                commandItem.appendChild(commandDesc);
                            }
                            
                            commandsList.appendChild(commandItem);
                        });
                        
                        toolCard.appendChild(commandsList);
                    }
                    
                    resultsSection.appendChild(toolCard);
                }
            });
        });
        
        if (!resultsFound) {
            const noResults = document.createElement('div');
            noResults.style.textAlign = 'center';
            noResults.style.padding = '30px';
            noResults.style.backgroundColor = 'var(--card-bg)';
            noResults.style.borderRadius = '8px';
            noResults.innerHTML = '<i class="fas fa-search" style="font-size: 3rem; color: var(--text-secondary); margin-bottom: 15px;"></i>' +
                                '<p>No results found for your search. Try different keywords.</p>';
            resultsSection.appendChild(noResults);
        }
        
        mainContent.appendChild(resultsSection);
        
        // Update page title
        document.title = `Search Results - XploitBase`;
    }
    
    function showLearnModal(command) {
        modalTitle.textContent = command.name || 'Command Details';
        
        let content = '';
        
        if (command.learn) {
            content += `<h3>${command.learn.title || 'Command Explanation'}</h3>`;
            content += `<div class="command-code">${command.command}</div>`;
            content += '<ul class="learn-details">';
            command.learn.details.forEach(detail => {
                content += `<li>${detail}</li>`;
            });
            content += '</ul>';
        } else {
            content += `<div class="command-code">${command.command}</div>`;
            if (command.description) {
                content += `<p>${command.description}</p>`;
            }
            
            // Generic explanation when specific learn details aren't available
            content += '<p class="note">This command is commonly used in CTF challenges. Try to understand its parameters and experiment with variations for different scenarios.</p>';
        }
        
        modalContent.innerHTML = content;
        modal.style.display = 'block';
    }
    
    function copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            showToast('Command copied to clipboard!');
        }).catch(err => {
            console.error('Failed to copy: ', err);
        });
    }
    
    function showToast(message) {
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.textContent = message;
        toast.style.position = 'fixed';
        toast.style.bottom = '20px';
        toast.style.left = '50%';
        toast.style.transform = 'translateX(-50%)';
        toast.style.backgroundColor = 'var(--accent-color)';
        toast.style.color = 'var(--bg-primary)';
        toast.style.padding = '10px 20px';
        toast.style.borderRadius = '4px';
        toast.style.zIndex = '1000';
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.5s ease';
            setTimeout(() => {
                toast.remove();
            }, 500);
        }, 2000);
    }
    
    // Build search index
    function buildSearchIndex() {
        searchIndex = [];
        if (typeof xploitBaseData !== 'undefined') {
            xploitBaseData.categories.forEach(category => {
                category.tools.forEach(tool => {
                    tool.commands.forEach(command => {
                        searchIndex.push({
                            category: category.name,
                            categoryId: category.id,
                            tool: tool.name,
                            commandName: command.name,
                            command: command.command,
                            description: command.description || '',
                            searchText: `${category.name} ${tool.name} ${command.name} ${command.command} ${command.description || ''}`.toLowerCase()
                        });
                    });
                });
            });
        }
        updateSearchStats();
    }
    
    // Perform instant search
    function performInstantSearch(query) {
        const startTime = performance.now();
        const queryLower = query.toLowerCase();
        const results = searchIndex.filter(item => 
            item.searchText.includes(queryLower)
        ).slice(0, 20);
        
        const endTime = performance.now();
        const searchTime = ((endTime - startTime) / 1000).toFixed(4);
        
        displaySearchResults(results, query, searchTime);
    }
    
    // Display search results
    function displaySearchResults(results, query, searchTime) {
        if (results.length === 0) {
            searchResults.innerHTML = `
                <div class="no-results">
                    <i class="fas fa-search"></i>
                    <p>No results found for "${query}"</p>
                    <p class="hint">Try different keywords or browse categories</p>
                </div>
            `;
            searchResults.style.display = 'block';
            searchStats.textContent = `${results.length} results in ${searchTime}s`;
            return;
        }
        
        let html = '<div class="results-grid">';
        results.forEach(result => {
            html += `
                <div class="result-card">
                    <div class="result-header">
                        <span class="result-category">${result.category}</span>
                        <span class="result-tool">${result.tool}</span>
                    </div>
                    <h3 class="result-title">${highlightMatch(result.commandName, query)}</h3>
                    <div class="result-command">
                        <code>${highlightMatch(result.command, query)}</code>
                        <button class="result-copy" data-command="${result.command.replaceAll('"', '&quot;')}" title="Copy command">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                    <p class="result-description">${highlightMatch(result.description, query)}</p>
                    <a href="categories/${result.categoryId}.html" class="result-link">
                        View in ${result.category} <i class="fas fa-arrow-right"></i>
                    </a>
                </div>
            `;
        });
        html += '</div>';
        
        searchResults.innerHTML = html;
        searchResults.style.display = 'block';
        searchStats.textContent = `${results.length} results in ${searchTime}s`;
        
        // Add copy functionality
        document.querySelectorAll('.result-copy').forEach(btn => {
            btn.addEventListener('click', function(e) {
                e.stopPropagation();
                const command = this.dataset.command;
                copyToClipboard(command);
            });
        });
    }
    
    // Highlight matched text
    function highlightMatch(text, query) {
        if (!text) return '';
        const regex = new RegExp(`(${query})`, 'gi');
        return text.replace(regex, '<mark>$1</mark>');
    }
    
    // Clear search results
    function clearSearchResults() {
        searchResults.innerHTML = '';
        searchResults.style.display = 'none';
        searchStats.textContent = '';
    }
    
    // Update search stats
    function updateSearchStats() {
        if (searchStats && searchIndex.length > 0) {
            searchStats.textContent = `${searchIndex.length} commands indexed`;
        }
    }
    
    // Add to recent searches
    function addToRecentSearches(query) {
        if (!recentSearches.includes(query)) {
            recentSearches.unshift(query);
            recentSearches = recentSearches.slice(0, 10);
            localStorage.setItem('recentSearches', JSON.stringify(recentSearches));
        }
    }
    
    // Copy to clipboard
    function copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            showToast('Command copied to clipboard!');
        }).catch(err => {
            console.error('Failed to copy:', err);
            showToast('Failed to copy command');
        });
    }
    
    // Show toast
    function showToast(message) {
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.textContent = message;
        toast.style.position = 'fixed';
        toast.style.bottom = '20px';
        toast.style.left = '50%';
        toast.style.transform = 'translateX(-50%)';
        toast.style.backgroundColor = 'var(--accent-color)';
        toast.style.color = '#fff';
        toast.style.padding = '12px 24px';
        toast.style.borderRadius = '6px';
        toast.style.zIndex = '10000';
        toast.style.boxShadow = '0 4px 12px rgba(0,0,0,0.3)';
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 2000);
    }
});
