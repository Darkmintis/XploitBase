// Main JavaScript for XploitBase

document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('searchInput');
    const searchBtn = document.getElementById('searchBtn');
    const categoryCards = document.querySelectorAll('.category-card');
    const modal = document.getElementById('learnModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalContent = document.getElementById('modalContent');
    const closeBtn = document.querySelector('.close');
    const themeToggleBtn = document.getElementById('themeToggle');
    
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
    
    // Handle category card clicks
    categoryCards.forEach(card => {
        card.addEventListener('click', function() {
            const categoryId = this.dataset.category;
            navigateToCategory(categoryId);
        });
    });
    
    // Handle search functionality
    searchBtn.addEventListener('click', performSearch);
    searchInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            performSearch();
        }
    });
    
    // Handle modal close
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
});
