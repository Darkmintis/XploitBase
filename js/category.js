// JavaScript for category pages

document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('searchInput');
    const searchBtn = document.getElementById('searchBtn');
    const modal = document.getElementById('learnModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalContent = document.getElementById('modalContent');
    const closeBtn = document.querySelector('.close');
    const themeToggleBtn = document.getElementById('themeToggle');// Theme Toggle functionality
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
    
    // Handle search functionality
    searchBtn.addEventListener('click', performSearch);
    searchInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            performSearch();
        }
    });
      // Get category ID from URL path
    const pathParts = globalThis.location.pathname.split('/');
    const htmlFilename = pathParts.at(-1);
    const categoryId = htmlFilename.replace('.html', '');
    
    // Load tools for the current category
    loadCategoryTools(categoryId);
    
    // Handle tool modal close if it exists
    const toolModal = document.getElementById('toolModal');
    const toolModalClose = document.querySelector('.tool-modal-close');
    if (toolModal && toolModalClose) {
        toolModalClose.addEventListener('click', function() {
            toolModal.style.display = 'none';
            document.body.style.overflow = 'auto'; // Re-enable scrolling
        });
        
        // Close tool modal when clicking outside
        globalThis.addEventListener('click', function(event) {
            if (event.target === toolModal) {
                toolModal.style.display = 'none';
                document.body.style.overflow = 'auto'; // Re-enable scrolling
            }
        });
    }
    
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
    function performSearch() {
        const searchTerm = searchInput.value.toLowerCase().trim();
        if (searchTerm === '') return;
        
        // Redirect to search results page
        globalThis.location.href = `../search.html?q=${encodeURIComponent(searchTerm)}`;
    }
      // Function to copy text to clipboard
    function copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            showToast('Command copied to clipboard!');
        }).catch(err => {
            console.error('Failed to copy: ', err);
        });
    }
    
    // Function to show toast notification
    function showToast(message) {
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.textContent = message;
        toast.style.position = 'fixed';
        toast.style.bottom = '20px';
        toast.style.left = '50%';
        toast.style.transform = 'translateX(-50%)';
        toast.style.backgroundColor = 'var(--accent-color)';
        toast.style.color = 'var(--bg-secondary)';
        toast.style.padding = '10px 20px';
        toast.style.borderRadius = '4px';
        toast.style.zIndex = '1500';
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.5s ease';
            setTimeout(() => {
                toast.remove();
            }, 500);
        }, 2000);
    }
      function showLearnModal(cmd) {
        // Set modal title
        modalTitle.textContent = cmd.name || 'Command Details';
        
        let content = '';
        
        if (cmd.learn) {
            content += `<h3>${cmd.learn.title || 'Command Explanation'}</h3>`;
            content += `<div class="command-code">${cmd.command}</div>`;
            content += '<ul class="learn-details">';
            cmd.learn.details.forEach(detail => {
                content += `<li>${detail}</li>`;
            });
            content += '</ul>';
        } else {
            content += `<div class="command-code">${cmd.command}</div>`;
            if (cmd.description) {
                content += `<p>${cmd.description}</p>`;
            }
            
            // Generic explanation when specific learn details aren't available
            content += '<p class="note">This command is commonly used in CTF challenges. Try to understand its parameters and experiment with variations for different scenarios.</p>';
        }
        
        modalContent.innerHTML = content;
        modal.style.display = 'block';
    }

    // Function to load tools for a category
    function loadCategoryTools(categoryId) {
        console.log("Loading category: ", categoryId);
        console.log("xploitBaseData available: ", typeof xploitBaseData !== 'undefined');
        
        const category = xploitBaseData.categories.find(cat => cat.id === categoryId);
        console.log("Category found: ", category);
        
        if (category) {
            // Update page title
            document.title = `${category.name} Tools - XploitBase`;
            
            // Set category title
            const categoryTitle = document.querySelector('.category-title');
            if (categoryTitle) {
                categoryTitle.textContent = `${category.name} Tools`;
            }
            
            // Get the tools grid container
            const toolsGrid = document.querySelector('.tools-grid');
            
            if (toolsGrid) {
                // Clear existing content
                toolsGrid.innerHTML = '';
                
                // Map tool types to Font Awesome icons
                const toolIcons = {
                    'scanner': 'fa-search',
                    'proxy': 'fa-random',
                    'exploitation': 'fa-bug',
                    'forensics': 'fa-magnifying-glass',
                    'networking': 'fa-network-wired',
                    'binary': 'fa-microchip',
                    'crypto': 'fa-key',
                    'database': 'fa-database',
                    'default': 'fa-tools'
                };
                
                // Create tool cards
                category.tools.forEach((tool, index) => {
                    // Determine the appropriate icon based on tool type or name
                    let iconClass = toolIcons.default;
                    if (tool.type && toolIcons[tool.type]) {
                        iconClass = toolIcons[tool.type];
                    } else if (tool.name.toLowerCase().includes('scan') || tool.name.toLowerCase().includes('recon')) {
                        iconClass = toolIcons.scanner;
                    } else if (tool.name.toLowerCase().includes('proxy') || tool.name.toLowerCase().includes('burp')) {
                        iconClass = toolIcons.proxy;
                    } else if (tool.name.toLowerCase().includes('sql') || tool.name.toLowerCase().includes('db')) {
                        iconClass = toolIcons.database;
                    }
                    
                    const toolCard = document.createElement('div');
                    toolCard.className = 'tool-grid-card';
                    toolCard.dataset.toolIndex = index;
                      toolCard.innerHTML = `
                        <div class="tool-icon">
                            <i class="fas ${iconClass}"></i>
                        </div>
                        <h3>${tool.name}</h3>
                        <div class="description">${tool.description}</div>
                    `;
                    
                    // Add click event to show tool details
                    toolCard.addEventListener('click', function() {
                        showToolDetails(category, tool);
                    });
                    
                    toolsGrid.appendChild(toolCard);
                });
            }
        }
    }
    
    // Function to show tool details in modal
    function showToolDetails(category, tool) {
        const toolModal = document.getElementById('toolModal');
        const toolModalContent = document.getElementById('toolModalContent');
        
        if (toolModal && toolModalContent) {
            // Determine appropriate icon
            const toolIcons = {
                'scanner': 'fa-search',
                'proxy': 'fa-random',
                'exploitation': 'fa-bug',
                'forensics': 'fa-magnifying-glass',
                'networking': 'fa-network-wired',
                'binary': 'fa-microchip',
                'crypto': 'fa-key',
                'database': 'fa-database',
                'default': 'fa-tools'
            };
            
            let iconClass = toolIcons.default;
            if (tool.type && toolIcons[tool.type]) {
                iconClass = toolIcons[tool.type];
            } else if (tool.name.toLowerCase().includes('scan') || tool.name.toLowerCase().includes('recon')) {
                iconClass = toolIcons.scanner;
            } else if (tool.name.toLowerCase().includes('proxy') || tool.name.toLowerCase().includes('burp')) {
                iconClass = toolIcons.proxy;
            } else if (tool.name.toLowerCase().includes('sql') || tool.name.toLowerCase().includes('db')) {
                iconClass = toolIcons.database;
            }
              // Create HTML content for tool modal
            let modalHTML = `
                <div class="tool-modal-header">
                    <div class="tool-modal-icon"><i class="fas ${iconClass}"></i></div>
                    <h2 class="tool-modal-title">${tool.name}</h2>
                </div>
                <div class="tool-modal-description">${tool.description}</div>
            `;
            
            // Add links if available
            if (tool.links && tool.links.length > 0) {
                modalHTML += '<div class="tool-modal-links">';
                tool.links.forEach(link => {
                    let linkIcon = 'fa-external-link-alt';
                    if (link.type === 'github') linkIcon = 'fa-github';
                    if (link.type === 'docs') linkIcon = 'fa-book';
                    if (link.type === 'download') linkIcon = 'fa-download';
                    
                    modalHTML += `
                        <a href="${link.url}" class="tool-modal-link" target="_blank" rel="noopener">
                            <i class="fas ${linkIcon}"></i> ${link.label || 'Visit'}
                        </a>
                    `;
                });
                modalHTML += '</div>';
            }
            
            // Add commands section
            if (tool.commands && tool.commands.length > 0) {
                modalHTML += '<div class="tool-modal-commands">';
                modalHTML += '<h4>Commands</h4>';
                modalHTML += '<div class="commands">';
                
                // Apply enhanced UI to all tools
                tool.commands.forEach(cmd => {
                    modalHTML += `
                        <div class="command-item enhanced">
                            <div class="command-box">
                                <div class="command-text">${cmd.command}</div>
                                <button class="copy-icon" title="Copy to clipboard" data-command="${cmd.command.replaceAll('"', '&quot;')}">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>
                            <div class="command-info-box">
                                <div class="command-description">${cmd.description || ''}</div>
                                ${cmd.learn ? `
                                    <div class="learn-icon" title="Learn more about this command">
                                        <i class="fas fa-book"></i>
                                        <div class="learn-tooltip">
                                            <h4>${cmd.learn.title || cmd.name}</h4>
                                            <ul>
                                                ${cmd.learn.details.map(detail => `<li>${detail}</li>`).join('')}
                                            </ul>
                                        </div>
                                    </div>
                                ` : ''}
                            </div>
                        </div>
                    `;
                });
                
                modalHTML += '</div></div>';
            }
            
            // Set modal content
            toolModalContent.innerHTML = modalHTML;
              // Add event listeners to the new buttons
            const copyButtons = toolModalContent.querySelectorAll('.copy-btn');
            copyButtons.forEach(btn => {
                btn.addEventListener('click', function(e) {
                    e.stopPropagation(); // Prevent event bubbling
                    const command = this.dataset.command;
                    copyToClipboard(command);
                });
            });
            
            // Add event listeners for enhanced UI copy icons
            const copyIcons = toolModalContent.querySelectorAll('.copy-icon');
            copyIcons.forEach(btn => {
                btn.addEventListener('click', function(e) {
                    e.stopPropagation(); // Prevent event bubbling
                    const command = this.dataset.command;
                    copyToClipboard(command);
                    
                    // Add to history
                    if (globalThis.XploitBaseHistory) {
                        XploitBaseHistory.add(command, tool.name, category.name);
                    }
                });
            });
            
            const learnButtons = toolModalContent.querySelectorAll('.learn-btn');
            learnButtons.forEach(btn => {
                btn.addEventListener('click', function(e) {
                    e.stopPropagation(); // Prevent event bubbling
                    const command = this.dataset.command;
                    const name = this.dataset.name;
                    const desc = this.dataset.desc;
                    
                    // Find the full command object for more details
                    const cmdObj = tool.commands.find(c => c.command === command);
                    showLearnModal(cmdObj || { command, name, description: desc });
                });
            });
            
            // Show the modal
            toolModal.style.display = 'block';
            document.body.style.overflow = 'hidden'; // Prevent scrolling behind modal
        }
    }
});

