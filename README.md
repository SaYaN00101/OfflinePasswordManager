# Offline Password Manager 🔐

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux-lightgrey)](https://github.com/SaYaN00101/OfflinePasswordManager)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/SaYaN00101/OfflinePasswordManager)

<div align="center">
  <img src="https://github.com/user-attachments/assets/bca05455-b2b3-4113-8e9d-6da933e9b7c5" alt="Password Manager Banner" width="800"/>
  <br>
  <p>
    <em>A secure, modern, and fully offline password management solution</em>
  </p>
</div>

## 📋 Overview

Offline Password Manager is a robust and secure solution for managing your passwords without any internet dependency. In today's world of frequent data breaches and privacy concerns, this application stands out by keeping your sensitive information completely offline and under your full control.

### 🛡️ Security First
- **Fully Offline**: Your passwords never leave your device
- **AES-256 Encryption**: Industry-standard encryption keeps your data secure
- **Zero Knowledge**: Master password is never stored, only its secure hash exists
- **Secure Memory**: Sensitive data is automatically cleared from RAM

### 💫 User Experience
- **Modern Interface**: Clean, intuitive design using CustomTkinter
- **Theme Options**: Comfortable viewing with dark and light modes
- **Quick Access**: Fast search and secure copy functionality
- **Password Generation**: Create strong passwords instantly

### 🔐 Built for Privacy
- **Local Storage**: Complete control over your password database
- **Smart Backups**: Automated daily encrypted backups
- **Secure Sharing**: Export/Import vaults with encryption
- **No Internet**: Works entirely offline for maximum security

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔒 **AES Encryption** | Military-grade encryption for all stored credentials |
| 🔑 **Master Password** | Single secure key to access your password vault |
| 💾 **Offline Storage** | All data stored locally, no internet required |
| 🎲 **Password Generator** | Create strong, random passwords with customizable options |
| 🔄 **Auto-Backup** | Daily automated backups of your encrypted vault |
| 🌓 **Theme Support** | Switch between light and dark themes |
| 📤 **Import/Export** | Securely transfer vaults between devices |
| 📋 **Clipboard Integration** | Quick copy passwords with automatic clearing |

## 🖼️ Screenshots

<div align="center">
  <img src="assets/login.png" alt="Login Screen" width="400"/>
  <p><em>Secure Login with Master Password</em></p>
  
  <img src="assets/dashboard.png" alt="Dashboard" width="400"/>
  <p><em>Modern Dashboard Interface</em></p>
  
  <img src="assets/add_password.png" alt="Add Password" width="400"/>
  <p><em>Add New Credentials with Strength Meter</em></p>
  
  <img src="assets/settings.png" alt="Settings" width="400"/>
  <p><em>Customizable Settings and Backup Options</em></p>
</div>

## 🛠️ Tech Stack

- **Python** 3.8+ - Core programming language
- **CustomTkinter** - Modern UI framework
- **Cryptography** - AES encryption implementation
- **Pyperclip** - Clipboard management
- **Threading** - Background tasks and auto-backup

## 📁 Project Structure

```
OfflinePasswordManager/
├── main.py              # Application entry point
├── ui.py               # User interface implementation
├── auth.py             # Authentication and master password handling
├── encryption.py       # Encryption/decryption utilities
├── storage.py          # Data storage and backup management
├── session.py          # Session management
├── utils.py            # Utility functions
├── password_generator.py# Password generation logic
├── requirements.txt    # Python dependencies
└── assets/            # Application images and resources
```

## ⚙️ Installation

1. Clone the repository
```bash
git clone https://github.com/yourusername/OfflinePasswordManager.git
cd OfflinePasswordManager
```

2. Create and activate virtual environment
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate     # Windows
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Run the application
```bash
python main.py
```

## 📖 Usage Guide

1. **First Launch**
   - Set up your master password
   - This password will encrypt all your stored credentials
   - Cannot be recovered if forgotten

2. **Managing Passwords**
   - Click "Add Password" to store new credentials
   - Use "View Passwords" to access stored items
   - Copy passwords directly to clipboard
   - Generate strong passwords with built-in tool

3. **Backup and Security**
   - Enable daily auto-backup in settings
   - Export vault for manual backup
   - All exports are encrypted with master password

4. **Customization**
   - Toggle between light/dark themes
   - Adjust auto-backup settings
   - Customize password generation rules

## 🔒 Security Implementation

- **Encryption**: AES-256 through Fernet symmetric encryption
- **Master Password**: Hashed using SHA-256
- **Storage**: All data encrypted at rest
- **Memory Protection**: Sensitive data cleared from memory
- **No Recovery**: Security over convenience approach

## 💾 Backup System

- **Automatic**: Daily backups when enabled
- **Location**: Local `backups/` directory
- **Format**: Encrypted ZIP archives
- **Retention**: Rolling 7-day backup history
- **Verification**: Integrity checking on backup creation

## 🚀 Future Enhancements

- [ ] Biometric authentication support
- [ ] Advanced password strength analysis
- [ ] Password expiration notifications
- [ ] Category management
- [ ] Optional cloud backup integration
- [ ] Password sharing capabilities
- [ ] Browser extension integration

## 📜 License

This project is licensed under the MIT License, which means:
- ✅ You can use this code for free
- ✅ You can use this code for commercial projects
- ✅ You can modify this code as you wish
- ✅ You can share this code with others
- ℹ️ You must include the original license and copyright notice
- ℹ️ The software comes with no warranty

See the [LICENSE](LICENSE) file for the full legal text.

## 🙏 Credits

- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) - Modern UI components
- [cryptography](https://github.com/pyca/cryptography) - Encryption implementation
- [pyperclip](https://github.com/asweigart/pyperclip) - Clipboard operations

## 👤 Author

Sayan Jagulia
- GitHub: https://github.com/SaYaN00101
- LinkedIn: www.linkedin.com/in/sayan-jagulia-s1y1n 

<div align="center">
  <img src="assets/footer.png" alt="Thank You" width="400"/>
  <p><em>Thank you for using Offline Password Manager!</em></p>
</div>

---
<div align="center">
  Made with ❤️ and Python

</div>

