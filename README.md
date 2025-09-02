# Secure Password Manager

A secure, dual-interface password management system built in Python. Developed as a Final Year Project for the Bachelor of Computer Applications (BCA) in Cloud and Security.

This project offers two interfaces to the same secure core: a Graphical User Interface (GUI) for everyday users and a Command-Line Interface (CLI) for power users and automation, both leveraging modern cryptography to solve password fatigue.

## 🔐 Core Security Features (Both Versions)

- Encryption: AES-256-GCM for confidential and authenticated encryption.
- Key Derivation: PBKDF2HMAC-SHA256 with 480,000 iterations and a unique salt.
- Data Integrity: The master password is validated by attempting to decrypt existing data before granting access.
- Zero-Knowledge: The master password is never stored. Only the encrypted vault (`vault.dat`) is persisted.
- Local-First: All data is encrypted and stored locally, giving you complete control.

## 🖥 ️ Graphical User Interface (GUI)

The primary user-friendly application (`password_manager_gui.py`) is built with Tkinter.

### Features:
- Secure login with a master password.
- Intuitive dashboard listing all saved services.
- Forms to add new credentials (service, username, password).
- One-click to reveal and copy credentials.
- Menu options to list services and check vault integrity.

### How to Run the GUI:
```bash
python password_manager_gui.py
```


## Command-Line Interface (CLI)
The lightweight, scriptable counterpart (password_manager.py) for the terminal.

Features:
Contains the exact same cryptographic security as the GUI.

Ideal for automation, remote sessions, or users who prefer the terminal.

CLI Commands & Usage:
# Add a new password for a service (will prompt for username and password)
```
python password_manager.py add <service_name>
```

# Retrieve and display credentials for a service
```
python password_manager.py get <service_name>
```

# List all services stored in the vault
```
python password_manager.py list
```

# Check the integrity of the vault and master password
```
python password_manager.py check
```

# Show help message
```
python password_manager.py --help
```

🚀 Getting Started
Prerequisites
Python 3.x

The cryptography library

Installation
1. Install the required library:
```
   pip install cryptography
```

2. Download the scripts:

password_manager_gui.py (for the GUI)

password_manager.py (for the CLI)

3. Run your preferred version (see instructions above)

Which Version Should I Use?
For Most Users: Use the GUI for its ease of use and visual feedback.

For Advanced Users/Scripting: Use the CLI for its speed and ability to be integrated into scripts.	

📁 Project Structure

secure-password-manager/

├── password_manager_gui.py  # Main GUI application

├── password_manager.py      # CLI application

├── vault.dat                # Encrypted vault (created automatically)

├── LICENSE

└── README.md


Note: Both applications read from and write to the same vault.dat file, allowing you to switch between them seamlessly.

🎓 Academic Note
This project was developed for the BCA (Cloud and Security) program at Amity University Online. It demonstrates practical application of cryptographic principles and user-centric design.

⚠️ Disclaimer
This is an academic proof-of-concept. While it uses strong encryption, it has not undergone a professional security audit. Use it as a learning resource.

👨‍💻 Developer
Kiwanuka Brian

Guide: Dr. Kateregga Daniel


