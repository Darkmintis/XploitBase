// CTF Timer and Task Tracker for XploitBase

document.addEventListener('DOMContentLoaded', function() {
    let timerInterval = null;
    let timerStartTime = null;
    let timerElapsed = 0;
    let timerPaused = false;
    
    globalThis.createTimerPanel = function() {
        const panel = document.createElement('div');
        panel.id = 'timerPanel';
        panel.className = 'side-panel timer-panel';
        panel.innerHTML = `
            <div class="panel-header">
                <h3><i class="fas fa-stopwatch"></i> CTF Timer & Tasks</h3>
                <button class="panel-close" onclick="document.getElementById('timerPanel').classList.remove('active')">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="panel-content">
                <div class="timer-section">
                    <div class="timer-display" id="timerDisplay">00:00:00</div>
                    <div class="timer-controls">
                        <button id="timerStart" class="timer-btn start-btn">
                            <i class="fas fa-play"></i> Start
                        </button>
                        <button id="timerPause" class="timer-btn pause-btn" style="display:none;">
                            <i class="fas fa-pause"></i> Pause
                        </button>
                        <button id="timerReset" class="timer-btn reset-btn">
                            <i class="fas fa-redo"></i> Reset
                        </button>
                    </div>
                </div>
                
                <div class="tasks-section">
                    <div class="tasks-header">
                        <h4><i class="fas fa-tasks"></i> Tasks</h4>
                        <button id="addTaskBtn" class="add-task-btn">
                            <i class="fas fa-plus"></i> Add Task
                        </button>
                    </div>
                    <div id="tasksList" class="tasks-list"></div>
                </div>
                
                <div class="challenge-info">
                    <h4><i class="fas fa-flag"></i> Challenge Info</h4>
                    <div class="info-field">
                        <label>Challenge Name:</label>
                        <input type="text" id="challengeName" placeholder="Enter challenge name">
                    </div>
                    <div class="info-field">
                        <label>Category:</label>
                        <select id="challengeCategory">
                            <option value="">Select category</option>
                            <option value="web">Web</option>
                            <option value="reverse">Reverse Engineering</option>
                            <option value="binary">Binary Exploitation</option>
                            <option value="crypto">Cryptography</option>
                            <option value="forensics">Forensics</option>
                            <option value="osint">OSINT</option>
                            <option value="stego">Steganography</option>
                            <option value="mobile">Mobile</option>
                            <option value="network">Networking</option>
                            <option value="misc">Miscellaneous</option>
                        </select>
                    </div>
                    <div class="info-field">
                        <label>Notes:</label>
                        <textarea id="challengeNotes" rows="4" placeholder="Add your notes here..."></textarea>
                    </div>
                    <button id="saveChallengeBtn" class="save-btn">
                        <i class="fas fa-save"></i> Save Challenge
                    </button>
                </div>
            </div>
        `;
        document.body.appendChild(panel);
        
        // Load saved timer state
        loadTimerState();
        
        // Timer controls
        document.getElementById('timerStart').addEventListener('click', startTimer);
        document.getElementById('timerPause').addEventListener('click', pauseTimer);
        document.getElementById('timerReset').addEventListener('click', resetTimer);
        
        // Task management
        document.getElementById('addTaskBtn').addEventListener('click', addTask);
        
        // Challenge info
        document.getElementById('saveChallengeBtn').addEventListener('click', saveChallenge);
        
        // Load tasks and challenge info
        loadTasks();
        loadChallengeInfo();
        
        // Auto-save timer state every second
        setInterval(saveTimerState, 1000);
    };
    
    function startTimer() {
        if (!timerStartTime) {
            timerStartTime = Date.now() - timerElapsed;
        }
        
        timerPaused = false;
        document.getElementById('timerStart').style.display = 'none';
        document.getElementById('timerPause').style.display = 'inline-block';
        
        timerInterval = setInterval(updateTimer, 1000);
    }
    
    function pauseTimer() {
        timerPaused = true;
        clearInterval(timerInterval);
        
        document.getElementById('timerStart').style.display = 'inline-block';
        document.getElementById('timerPause').style.display = 'none';
    }
    
    function resetTimer() {
        if (confirm('Reset timer? This will clear your current time.')) {
            clearInterval(timerInterval);
            timerStartTime = null;
            timerElapsed = 0;
            timerPaused = false;
            
            document.getElementById('timerDisplay').textContent = '00:00:00';
            document.getElementById('timerStart').style.display = 'inline-block';
            document.getElementById('timerPause').style.display = 'none';
            
            localStorage.removeItem('xploitbase_timer_state');
        }
    }
    
    function updateTimer() {
        if (!timerPaused && timerStartTime) {
            timerElapsed = Date.now() - timerStartTime;
            displayTime(timerElapsed);
        }
    }
    
    function displayTime(ms) {
        const totalSeconds = Math.floor(ms / 1000);
        const hours = Math.floor(totalSeconds / 3600);
        const minutes = Math.floor((totalSeconds % 3600) / 60);
        const seconds = totalSeconds % 60;
        
        const display = [hours, minutes, seconds]
            .map(n => n.toString().padStart(2, '0'))
            .join(':');
        
        document.getElementById('timerDisplay').textContent = display;
    }
    
    function saveTimerState() {
        const state = {
            startTime: timerStartTime,
            elapsed: timerElapsed,
            paused: timerPaused
        };
        localStorage.setItem('xploitbase_timer_state', JSON.stringify(state));
    }
    
    function loadTimerState() {
        const saved = localStorage.getItem('xploitbase_timer_state');
        if (saved) {
            const state = JSON.parse(saved);
            timerStartTime = state.startTime;
            timerElapsed = state.elapsed;
            timerPaused = state.paused;
            
            if (timerStartTime && !timerPaused) {
                startTimer();
            } else {
                displayTime(timerElapsed);
            }
        }
    }
    
    function addTask() {
        const taskText = prompt('Enter task description:');
        if (taskText?.trim()) {
            const tasks = getTasks();
            const task = {
                id: Date.now().toString(),
                text: taskText.trim(),
                completed: false,
                createdAt: new Date().toISOString()
            };
            tasks.push(task);
            saveTasks(tasks);
            loadTasks();
        }
    }
    
    function getTasks() {
        return JSON.parse(localStorage.getItem('xploitbase_tasks') || '[]');
    }
    
    function saveTasks(tasks) {
        localStorage.setItem('xploitbase_tasks', JSON.stringify(tasks));
    }
    
    function loadTasks() {
        const tasks = getTasks();
        const tasksList = document.getElementById('tasksList');
        
        if (!tasksList) return;
        
        if (tasks.length === 0) {
            tasksList.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-tasks"></i>
                    <p>No tasks yet</p>
                </div>
            `;
            return;
        }
        
        let html = '';
        tasks.forEach(task => {
            html += `
                <div class="task-item ${task.completed ? 'completed' : ''}">
                    <input type="checkbox" ${task.completed ? 'checked' : ''} 
                           onchange="toggleTask('${task.id}')" class="task-checkbox">
                    <span class="task-text">${task.text}</span>
                    <button class="task-delete" onclick="deleteTask('${task.id}')">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `;
        });
        tasksList.innerHTML = html;
    }
    
    globalThis.toggleTask = function(id) {
        const tasks = getTasks();
        const task = tasks.find(t => t.id === id);
        if (task) {
            task.completed = !task.completed;
            saveTasks(tasks);
            renderTasks();
        }
    };
    
    globalThis.deleteTask = function(id) {
        let tasks = getTasks();
        tasks = tasks.filter(t => t.id !== id);
        saveTasks(tasks);
        loadTasks();
    };
    
    function saveChallenge() {
        const challenge = {
            name: document.getElementById('challengeName').value,
            category: document.getElementById('challengeCategory').value,
            notes: document.getElementById('challengeNotes').value,
            savedAt: new Date().toISOString()
        };
        
        localStorage.setItem('xploitbase_current_challenge', JSON.stringify(challenge));
        showToast('Challenge info saved!');
    }
    
    function loadChallengeInfo() {
        const saved = localStorage.getItem('xploitbase_current_challenge');
        if (saved) {
            const challenge = JSON.parse(saved);
            const nameInput = document.getElementById('challengeName');
            const categorySelect = document.getElementById('challengeCategory');
            const notesTextarea = document.getElementById('challengeNotes');
            
            if (nameInput) nameInput.value = challenge.name || '';
            if (categorySelect) categorySelect.value = challenge.category || '';
            if (notesTextarea) notesTextarea.value = challenge.notes || '';
        }
    }
});
