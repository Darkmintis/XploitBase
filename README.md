# XploitBase - Your Ultimate CTF Companion

XploitBase is a **self-contained, offline-ready toolkit** for CTF players. In the AI-driven world, XploitBase provides everything you need—standard tools, commands, and techniques—without external dependencies. Just open it and start solving challenges.

## ✨ Features

### 🚀 Core Features
- **16 CTF Categories**: Web, Reverse Engineering, Binary Exploitation, Cryptography, Forensics, OSINT, Steganography, Mobile, Networking, Miscellaneous, IDOR & Auth, Privilege Escalation, Active Directory, System Exploitation, Malware Analysis, and Real World/Full Pwn
- **Extensive Tool Database**: Hundreds of tools with detailed command examples and explanations
- **Tool Type Badges**: Visual indicators for Software, CLI Tools, Websites, Steps, and Frameworks
- **Enhanced Command UI**: Boxed commands with copy buttons and learn icons
- **Smart Search**: Fast and efficient search across all tools and commands
- **Dark/Light Themes**: Toggle between themes with persistent preference

### ⚡ Advanced Features
- **Keyboard Shortcuts**: Navigate faster with comprehensive keyboard shortcuts
  - `Ctrl/Cmd + K` - Focus search
  - `Ctrl/Cmd + F` - Toggle favorites
  - `Ctrl/Cmd + N` - Toggle notes
  - `Ctrl/Cmd + T` - Toggle CTF timer
  - `Ctrl/Cmd + Q` - Quick cheat sheet
  - `Ctrl/Cmd + /` - Show all shortcuts
  - `Esc` - Close modals

- **Favorites & History System**
  - Save your frequently used commands
  - Automatic command history tracking
  - Quick copy from favorites/history
  - Export favorites and history

- **CTF Timer & Task Tracker**
  - Built-in stopwatch for timing challenges
  - Task list with completion tracking
  - Challenge information storage
  - Auto-save functionality

- **Notes System**
  - Create and manage CTF notes
  - Markdown export functionality
  - Quick access to all notes
  - Timestamps for all notes

- **Quick Cheat Sheet**
  - Instant access to common CTF commands
  - Organized by category (Network, Web, Crypto, etc.)
  - Copy commands with one click

- **Offline Support**
  - Service Worker for offline functionality
  - Cache all resources for offline access
  - Work without internet connection

- **Data Export**
  - Export favorites, history, and notes
  - JSON format for easy backup
  - Restore from exported data

### 🎨 UI/UX Features
- **Floating Action Button (FAB)**: Quick access to all features
- **Side Panels**: Non-intrusive panels for favorites, notes, and timer
- **Toast Notifications**: Instant feedback for user actions
- **Responsive Design**: Works on desktop, tablet, and mobile
- **Modern UI**: Clean, professional interface with smooth animations
- **Accessibility**: Keyboard navigation and ARIA labels

## 📁 Project Structure

```
XploitBase/
├── index.html              # Main homepage
├── search.html             # Search results page
├── help.html               # Help and documentation
├── sw.js                   # Service Worker for offline support
├── categories/             # Category pages (16 files)
│   ├── web.html
│   ├── reverse.html
│   ├── binary.html
│   └── ... (13 more)
├── css/
│   ├── styles.css          # Main styles
│   ├── command-enhancements.css  # Command UI styles
│   └── enhanced-features.css     # Advanced features styles
├── js/
│   ├── data.js             # All tools and commands data
│   ├── main.js             # Main page functionality
│   ├── category.js         # Category page functionality
│   ├── search.js           # Search functionality
│   ├── shortcuts.js        # Keyboard shortcuts & cheat sheet
│   ├── favorites.js        # Favorites & history management
│   ├── timer.js            # CTF timer & task tracker
│   └── notes.js            # Notes system
└── images/                 # Images and icons
```

## 🚀 Getting Started

### Installation

1. **Clone or download** this repository:
   ```bash
   git clone https://github.com/Darkmintis/XploitBase.git
   cd XploitBase
   ```

2. **Open in browser**:
   - Simply open `index.html` in your web browser
   - Or use a local server:
     ```bash
     python3 -m http.server 8000
     # Visit http://localhost:8000
     ```

3. **Optional: Deploy to web server**:
   - Upload all files to your web hosting
   - Access via your domain

### First Time Setup

1. **Explore Categories**: Click on any category to see available tools
2. **Try Keyboard Shortcuts**: Press `Ctrl/Cmd + /` to see all shortcuts
3. **Set Your Theme**: Click the theme toggle button (moon/sun icon)
4. **Add Favorites**: Click stars on commands you use frequently
5. **Create Notes**: Press `Ctrl/Cmd + N` to open notes panel
6. **Start Timer**: Press `Ctrl/Cmd + T` for CTF timer

## 💡 Usage Guide

### Quick Start
1. **Search for tools**: Use the search bar (or press `Ctrl/Cmd + K`)
2. **Browse categories**: Click on category cards on the homepage
3. **View tool details**: Click on any tool to see commands and details
4. **Copy commands**: Click the copy icon next to any command
5. **Learn more**: Hover over the book icon for detailed explanations

### Advanced Usage

#### Using Favorites
1. When viewing a command, copy it (it's automatically added to history)
2. Open Favorites panel (`Ctrl/Cmd + F`)
3. Switch to History tab to see recent commands
4. Click star icon to add to favorites

#### Creating Notes
1. Press `Ctrl/Cmd + N` to open Notes panel
2. Click "New Note" button
3. Enter title and content
4. Click "Save" to store the note
5. Export notes as Markdown when needed

#### Using CTF Timer
1. Press `Ctrl/Cmd + T` to open Timer panel
2. Click "Start" to begin timing
3. Add tasks to track your progress
4. Fill in challenge information for reference
5. Timer auto-saves and persists across sessions

#### Quick Cheat Sheet
1. Press `Ctrl/Cmd + Q` to open cheat sheet
2. Browse common commands by category
3. Click to copy any command
4. Perfect for quick reference during CTFs

## 🔧 Customization

### Adding New Tools
Edit `js/data.js` and add your tool to the appropriate category:

```javascript
{
    name: "Tool Name",
    description: "Brief description",
    type: "tool-type",
    toolType: "🔧 CLI Tool",
    commands: [
        {
            name: "Command Name",
            command: "actual command",
            description: "What it does",
            learn: {
                title: "Learn More",
                details: [
                    "Detail 1",
                    "Detail 2"
                ]
            }
        }
    ]
}
```

### Customizing Themes
Modify CSS variables in `css/styles.css`:

```css
:root {
    --accent-color: #667eea;  /* Change accent color */
    --bg-primary: #1a1a2e;    /* Background color */
    /* ... more variables */
}
```

## 📱 Keyboard Shortcuts Reference

| Shortcut | Action |
|----------|--------|
| `Ctrl/Cmd + K` | Focus search bar |
| `Ctrl/Cmd + H` | Go to home |
| `Ctrl/Cmd + F` | Toggle favorites panel |
| `Ctrl/Cmd + N` | Toggle notes panel |
| `Ctrl/Cmd + T` | Toggle CTF timer |
| `Ctrl/Cmd + Q` | Quick cheat sheet |
| `Ctrl/Cmd + E` | Export data |
| `Ctrl/Cmd + B` | Toggle theme |
| `Ctrl/Cmd + /` | Show shortcuts help |
| `Esc` | Close modals/panels |

## 🌐 Browser Support

- ✅ Chrome/Edge (recommended)
- ✅ Firefox
- ✅ Safari
- ✅ Opera
- ⚠️ IE11 (limited support)

## 📊 Features Comparison

| Feature | XploitBase | Other CTF Tools |
|---------|-----------|-----------------|
| Offline Support | ✅ | ❌ |
| Command History | ✅ | ❌ |
| Favorites System | ✅ | ❌ |
| CTF Timer | ✅ | ❌ |
| Notes System | ✅ | ❌ |
| Keyboard Shortcuts | ✅ | ❌ |
| Quick Cheat Sheet | ✅ | ❌ |
| Export Functionality | ✅ | ❌ |
| Dark/Light Theme | ✅ | ⚠️ |
| Mobile Responsive | ✅ | ⚠️ |

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Add new tools**: Submit PRs with new tools and commands
2. **Improve documentation**: Help improve the help pages
3. **Report bugs**: Open issues for any bugs you find
4. **Suggest features**: Share ideas for new features
5. **Translations**: Help translate to other languages

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Font Awesome for icons
- CTF community for tool suggestions
- All contributors and users

## Contact

- **GitHub**: [Darkmintis](https://github.com/Darkmintis)
- **Website**: [darkmintis.dev](https://darkmintis.dev)
- **Issues**: [GitHub Issues](https://github.com/Darkmintis/XploitBase/issues)

## 🔄 Changelog

### Version 2.0.0 (Latest)
- ✨ Added keyboard shortcuts
- ✨ Implemented favorites and history system
- ✨ Created CTF timer and task tracker
- ✨ Added notes system with export
- ✨ Implemented offline support with Service Worker
- ✨ Added quick cheat sheet modal
- ✨ Floating Action Button for quick access
- ✨ Export functionality for all data
- 🎨 Enhanced UI with better command display
- 🐛 Various bug fixes and improvements

### Version 1.0.0
- 🎉 Initial release
- 📚 16 CTF categories
- 🔧 Hundreds of tools and commands
- 🎨 Dark/Light theme support
- 🔍 Search functionality
- 📱 Responsive design

---

**Made with ❤️ for the CTF community**

*XploitBase - Making CTFs easier, one command at a time.*
