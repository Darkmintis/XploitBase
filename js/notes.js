// Notes System for XploitBase

document.addEventListener('DOMContentLoaded', function() {
    window.createNotesPanel = function() {
        const panel = document.createElement('div');
        panel.id = 'notesPanel';
        panel.className = 'side-panel notes-panel';
        panel.innerHTML = `
            <div class="panel-header">
                <h3><i class="fas fa-sticky-note"></i> CTF Notes</h3>
                <button class="panel-close" onclick="document.getElementById('notesPanel').classList.remove('active')">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="panel-content">
                <div class="notes-tools">
                    <button id="newNoteBtn" class="notes-btn">
                        <i class="fas fa-plus"></i> New Note
                    </button>
                    <button id="exportNotesBtn" class="notes-btn">
                        <i class="fas fa-download"></i> Export
                    </button>
                </div>
                <div id="notesList" class="notes-list"></div>
            </div>
        `;
        document.body.appendChild(panel);
        
        document.getElementById('newNoteBtn').addEventListener('click', createNewNote);
        document.getElementById('exportNotesBtn').addEventListener('click', exportNotes);
        
        loadNotes();
    };
    
    function createNewNote() {
        const title = prompt('Note title:');
        if (!title || !title.trim()) return;
        
        const notes = getNotes();
        const note = {
            id: Date.now().toString(),
            title: title.trim(),
            content: '',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        
        notes.push(note);
        saveNotes(notes);
        loadNotes();
        editNote(note.id);
    }
    
    function getNotes() {
        return JSON.parse(localStorage.getItem('xploitbase_notes') || '[]');
    }
    
    function saveNotes(notes) {
        localStorage.setItem('xploitbase_notes', JSON.stringify(notes));
    }
    
    function loadNotes() {
        const notes = getNotes();
        const notesList = document.getElementById('notesList');
        
        if (!notesList) return;
        
        if (notes.length === 0) {
            notesList.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-sticky-note"></i>
                    <p>No notes yet</p>
                    <small>Click "New Note" to create one</small>
                </div>
            `;
            return;
        }
        
        // Sort by most recently updated
        notes.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
        
        let html = '';
        notes.forEach(note => {
            const preview = note.content.substring(0, 100) || 'Empty note';
            const date = new Date(note.updatedAt).toLocaleString();
            
            html += `
                <div class="note-card" data-id="${note.id}">
                    <div class="note-header">
                        <h4>${note.title}</h4>
                        <div class="note-actions">
                            <button class="note-edit" onclick="editNote('${note.id}')" title="Edit">
                                <i class="fas fa-edit"></i>
                            </button>
                            <button class="note-delete" onclick="deleteNote('${note.id}')" title="Delete">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </div>
                    <div class="note-preview">${preview}</div>
                    <div class="note-date">${date}</div>
                </div>
            `;
        });
        
        notesList.innerHTML = html;
    }
    
    window.editNote = function(id) {
        const notes = getNotes();
        const note = notes.find(n => n.id === id);
        
        if (!note) return;
        
        // Create edit modal
        let modal = document.getElementById('noteEditModal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'noteEditModal';
            modal.className = 'modal';
            document.body.appendChild(modal);
        }
        
        modal.innerHTML = `
            <div class="modal-content note-editor">
                <div class="note-editor-header">
                    <input type="text" id="noteTitle" class="note-title-input" value="${note.title}">
                    <button class="save-note-btn" onclick="saveCurrentNote('${id}')">
                        <i class="fas fa-save"></i> Save
                    </button>
                    <span class="close" onclick="document.getElementById('noteEditModal').style.display='none'">&times;</span>
                </div>
                <textarea id="noteContent" class="note-content-editor">${note.content}</textarea>
                <div class="note-editor-footer">
                    <small>Created: ${new Date(note.createdAt).toLocaleString()}</small>
                    <small>Updated: ${new Date(note.updatedAt).toLocaleString()}</small>
                </div>
            </div>
        `;
        
        modal.style.display = 'block';
        document.getElementById('noteContent').focus();
    };
    
    window.saveCurrentNote = function(id) {
        const notes = getNotes();
        const note = notes.find(n => n.id === id);
        
        if (!note) return;
        
        note.title = document.getElementById('noteTitle').value;
        note.content = document.getElementById('noteContent').value;
        note.updatedAt = new Date().toISOString();
        
        saveNotes(notes);
        loadNotes();
        
        document.getElementById('noteEditModal').style.display = 'none';
        showToast('Note saved!');
    };
    
    window.deleteNote = function(id) {
        if (confirm('Delete this note?')) {
            let notes = getNotes();
            notes = notes.filter(n => n.id !== id);
            saveNotes(notes);
            loadNotes();
            showToast('Note deleted');
        }
    };
    
    function exportNotes() {
        const notes = getNotes();
        
        if (notes.length === 0) {
            showToast('No notes to export');
            return;
        }
        
        // Create markdown format
        let markdown = '# XploitBase CTF Notes\n\n';
        markdown += `Exported: ${new Date().toLocaleString()}\n\n`;
        markdown += '---\n\n';
        
        notes.forEach(note => {
            markdown += `## ${note.title}\n\n`;
            markdown += `**Created:** ${new Date(note.createdAt).toLocaleString()}\n`;
            markdown += `**Updated:** ${new Date(note.updatedAt).toLocaleString()}\n\n`;
            markdown += note.content + '\n\n';
            markdown += '---\n\n';
        });
        
        const blob = new Blob([markdown], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `xploitbase-notes-${new Date().toISOString().split('T')[0]}.md`;
        a.click();
        URL.revokeObjectURL(url);
        
        showToast('Notes exported successfully!');
    }
});
