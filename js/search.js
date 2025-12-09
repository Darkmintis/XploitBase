// JavaScript for search results page

document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('searchInput');
    const searchBtn = document.getElementById('searchBtn');
    const searchTitle = document.getElementById('searchTitle');
    const searchResults = document.getElementById('searchResults');
    const modal = document.getElementById('learnModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalContent = document.getElementById('modalContent');
    const closeBtn = document.querySelector('.close');
    const themeToggleBtn = document.getElementById('themeToggle');    // Theme Toggle functionality
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
        // Toggle theme class on body
        document.body.classList.toggle('light-theme');
        
        // Update theme in localStorage
        if (document.body.classList.contains('light-theme')) {
            localStorage.setItem('theme', 'light');
            themeToggleBtn.innerHTML = '<i class="fas fa-sun"></i>';
        } else {
            localStorage.setItem('theme', 'dark');
            themeToggleBtn.innerHTML = '<i class="fas fa-moon"></i>';
        }
    });
    
    // Parse search query from URL
    const urlParams = new URLSearchParams(window.location.search);
    const searchQuery = urlParams.get('q');
    
    // Set search input value to query
    if (searchQuery) {
        searchInput.value = searchQuery;
        searchTitle.textContent = `Search Results for "${searchQuery}"`;
        performSearch(searchQuery);
    }
    
    // Handle new search
    searchBtn.addEventListener('click', function() {
        const newSearchTerm = searchInput.value.toLowerCase().trim();
        if (newSearchTerm === '') return;
        
        // Update URL
        window.history.pushState({}, '', `search.html?q=${encodeURIComponent(newSearchTerm)}`);
        
        // Update title and perform search
        searchTitle.textContent = `Search Results for "${newSearchTerm}"`;
        performSearch(newSearchTerm);
    });
    
    searchInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            searchBtn.click();
        }
    });
    
    // Handle modal close
    if(closeBtn) {
        closeBtn.addEventListener('click', function() {
            modal.style.display = 'none';
        });
    }
    
    // Close modal when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
    
    // Functions
    function performSearch(searchTerm) {
        // Clear previous results
        searchResults.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Searching...</div>';
        
        // Short delay to show loading indicator
        setTimeout(() => {
            searchResults.innerHTML = '';
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
                        (cmd.name && cmd.name.toLowerCase().includes(searchTerm)) || 
                        (cmd.command && cmd.command.toLowerCase().includes(searchTerm)) || 
                        (cmd.description && cmd.description.toLowerCase().includes(searchTerm))
                    );
                    
                    if (toolMatches || commandMatches.length > 0) {
                        resultsFound = true;
                        
                        const toolCard = document.createElement('div');
                        toolCard.className = 'tool-card';
                        
                        const toolHeader = document.createElement('h3');
                        toolHeader.innerHTML = `${tool.name} <span class="category-tag">${category.name}</span>`;
                        
                        const toolDesc = document.createElement('div');
                        toolDesc.className = 'description';
                        toolDesc.textContent = tool.description;
                        
                        toolCard.appendChild(toolHeader);
                        toolCard.appendChild(toolDesc);
                        
                        // Add commands section if there are matching commands
                        if (commandMatches.length > 0 || toolMatches) {
                            const commandsTitle = document.createElement('h4');
                            commandsTitle.textContent = 'Commands:';
                            toolCard.appendChild(commandsTitle);
                            
                            const commandsList = document.createElement('div');
                            commandsList.className = 'commands';
                            
                            // If the tool itself matches, show all commands
                            const cmdsToShow = toolMatches ? tool.commands : commandMatches;
                            
                            cmdsToShow.forEach(cmd => {
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
                                    
                                    // Show copied feedback
                                    const originalHTML = this.innerHTML;
                                    this.innerHTML = '<i class="fas fa-check"></i>';
                                    this.style.backgroundColor = '#4CAF50';
                                    
                                    setTimeout(() => {
                                        this.innerHTML = originalHTML;
                                        this.style.backgroundColor = '';
                                    }, 1500);
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
                        
                        searchResults.appendChild(toolCard);
                    }
                });
            });
            
            // If no results found
            if (!resultsFound) {
                const noResults = document.createElement('div');
                noResults.className = 'no-results';
                noResults.innerHTML = '<i class="fas fa-search"></i><p>No results found for your search.</p>';
                searchResults.appendChild(noResults);
            }
        }, 300);
    }
    
    function copyToClipboard(text) {
        // Create temporary element
        const el = document.createElement('textarea');
        el.value = text;
        document.body.appendChild(el);
        el.select();
        document.execCommand('copy');
        document.body.removeChild(el);
    }
    
    function showLearnModal(cmd) {
        // Set modal title
        modalTitle.textContent = cmd.learn ? cmd.learn.title : (cmd.name || 'Command Details');
        
        // Clear previous content
        modalContent.innerHTML = '';
        
        // Add command
        const commandEl = document.createElement('div');
        commandEl.className = 'modal-command';
        commandEl.innerHTML = `<pre>${cmd.command}</pre>`;
        modalContent.appendChild(commandEl);
        
        // Add description if available
        if (cmd.description) {
            const descEl = document.createElement('p');
            descEl.className = 'modal-description';
            descEl.textContent = cmd.description;
            modalContent.appendChild(descEl);
        }
        
        // Add learn details if available
        if (cmd.learn && cmd.learn.details && cmd.learn.details.length > 0) {
            const detailsEl = document.createElement('ul');
            detailsEl.className = 'modal-details';
            
            cmd.learn.details.forEach(detail => {
                const li = document.createElement('li');
                li.textContent = detail;
                detailsEl.appendChild(li);
            });
            
            modalContent.appendChild(detailsEl);
        }
        
        // Show modal
        modal.style.display = 'block';
    }
});
