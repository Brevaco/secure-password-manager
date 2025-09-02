# password_manager_gui.py
"""
SECURE PASSWORD MANAGER WITH GUI
BCA Final Year Project (Cloud and Security)
Amity University Online

Graphical user interface for the secure password management system.
Provides easy access to all features through buttons and forms.
"""

import json
import base64
import os
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from getpass import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constants
DATA_FILE = "vault.dat"
ITERATIONS = 480000

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager - BCA Project")
        self.root.geometry("800x600")
        self.root.configure(bg='#2c3e50')
        
        self.key = None
        self.vault_data = {}
        
        self.setup_styles()
        self.create_welcome_screen()
        
    def setup_styles(self):
        """Configure styles for the GUI elements"""
        self.style = ttk.Style()
        self.style.configure('Title.TLabel', 
                            font=('Arial', 16, 'bold'), 
                            background='#2c3e50', 
                            foreground='white')
        self.style.configure('Normal.TLabel', 
                            font=('Arial', 10), 
                            background='#2c3e50', 
                            foreground='white')
        self.style.configure('Button.TButton', 
                            font=('Arial', 10, 'bold'),
                            padding=10)
        self.style.configure('Listbox.TFrame', 
                            background='#34495e')
    
    def clear_window(self):
        """Clear all widgets from the window"""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def create_welcome_screen(self):
        """Create the welcome/authentication screen"""
        self.clear_window()
        
        # Title frame
        title_frame = ttk.Frame(self.root, style='Title.TLabel')
        title_frame.pack(pady=50)
        
        ttk.Label(title_frame, 
                 text="🔐 SECURE PASSWORD MANAGER", 
                 style='Title.TLabel').pack()
        ttk.Label(title_frame, 
                 text="BCA Final Year Project - Cloud and Security", 
                 style='Normal.TLabel').pack(pady=5)
        
        # Login frame
        login_frame = ttk.Frame(self.root, style='Normal.TLabel')
        login_frame.pack(pady=30)
        
        ttk.Label(login_frame, 
                 text="Enter Master Password:", 
                 style='Normal.TLabel').pack(pady=10)
        
        self.master_password = tk.StringVar()
        password_entry = ttk.Entry(login_frame, 
                                  textvariable=self.master_password, 
                                  show='*', 
                                  width=30,
                                  font=('Arial', 12))
        password_entry.pack(pady=10)
        password_entry.bind('<Return>', lambda e: self.authenticate())  # Enter key to submit
        
        # Buttons
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, 
                  text="Login", 
                  command=self.authenticate,
                  style='Button.TButton').pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, 
                  text="Exit", 
                  command=self.root.quit,
                  style='Button.TButton').pack(side=tk.LEFT, padx=10)
        
        # Focus on password entry
        password_entry.focus()
    
    def validate_master_password(self, key):
        """
        Validate that the derived key can decrypt existing vault data.
        Returns True if authentication is successful, False otherwise.
        """
        if not self.vault_data.get('services'):
            # Empty vault - any password is valid for first use
            return True
            
        # Try to decrypt the first service entry to validate the key
        try:
            first_service = next(iter(self.vault_data['services']))
            encrypted_data = self.vault_data['services'][first_service]
            self.decrypt_data(encrypted_data, key)
            return True
        except Exception as e:
            # Decryption failed - wrong password
            return False
    
    def authenticate(self):
        """Authenticate user with master password"""
        master_pwd = self.master_password.get()
        
        if not master_pwd:
            messagebox.showerror("Error", "Master password cannot be empty!")
            return
        
        try:
            self.vault_data = self.load_vault_metadata()
            salt = base64.b64decode(self.vault_data.get('vault_salt', '')) if self.vault_data.get('vault_salt') else None
            
            self.key, new_salt = self.derive_key(master_pwd, salt)
            
            # Validate that the key can decrypt existing data
            if not self.validate_master_password(self.key):
                messagebox.showerror("Authentication Failed", 
                                    "Incorrect master password!")
                return
            
            # Store salt if this is a new vault
            if salt is None:
                self.vault_data['vault_salt'] = base64.b64encode(new_salt).decode('utf-8')
                self.save_vault_metadata(self.vault_data)
            
            self.create_main_interface()
            
        except Exception as e:
            messagebox.showerror("Authentication Failed", 
                                f"Failed to authenticate: {str(e)}")
    
    def create_main_interface(self):
        """Create the main application interface"""
        self.clear_window()
        
        # Header
        header_frame = ttk.Frame(self.root, style='Title.TLabel')
        header_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(header_frame, 
                 text="🔐 Password Manager Dashboard", 
                 style='Title.TLabel').pack()
        
        # Button panel
        button_frame = ttk.Frame(self.root)
        button_frame.pack(fill=tk.X, pady=10, padx=20)
        
        ttk.Button(button_frame, 
                  text="➕ Add Password", 
                  command=self.add_password_dialog,
                  style='Button.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, 
                  text="👁️ View Password", 
                  command=self.view_password_dialog,
                  style='Button.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, 
                  text="📋 List Services", 
                  command=self.list_services,
                  style='Button.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, 
                  text="✅ Check Vault", 
                  command=self.check_vault,
                  style='Button.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, 
                  text="🚪 Logout", 
                  command=self.create_welcome_screen,
                  style='Button.TButton').pack(side=tk.RIGHT, padx=5)
        
        # Status area
        self.status_var = tk.StringVar()
        self.status_var.set("Ready. Select an action from above.")
        status_label = ttk.Label(self.root, 
                                textvariable=self.status_var,
                                style='Normal.TLabel')
        status_label.pack(pady=10)
        
        # Services listbox
        list_frame = ttk.Frame(self.root, style='Listbox.TFrame')
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        ttk.Label(list_frame, 
                 text="Your Services:",
                 style='Normal.TLabel').pack(anchor=tk.W)
        
        self.services_listbox = tk.Listbox(list_frame, 
                                         height=15,
                                         font=('Arial', 10),
                                         bg='#34495e',
                                         fg='white',
                                         selectbackground='#3498db')
        self.services_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        self.services_listbox.bind('<Double-Button-1>', self.on_service_double_click)
        
        self.update_services_list()
    
    def update_services_list(self):
        """Update the services listbox"""
        self.services_listbox.delete(0, tk.END)
        if 'services' in self.vault_data:
            for service in sorted(self.vault_data['services'].keys()):
                self.services_listbox.insert(tk.END, service)
    
    def on_service_double_click(self, event):
        """Handle double-click on a service in the list"""
        selection = self.services_listbox.curselection()
        if selection:
            service = self.services_listbox.get(selection[0])
            self.view_password(service)
    
    def add_password_dialog(self):
        """Dialog for adding a new password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add New Password")
        dialog.geometry("400x300")
        dialog.configure(bg='#2c3e50')
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Create a style for this dialog with visible button text
        dialog_style = ttk.Style()
        dialog_style.configure('Dialog.TLabel', 
                              font=('Arial', 10), 
                              background='#2c3e50', 
                              foreground='white')
        dialog_style.configure('Dialog.TButton', 
                              font=('Arial', 10, 'bold'),
                              padding=5,
                              foreground='black')  # Black text for visibility
        
        ttk.Label(dialog, 
                 text="Add New Service Credentials",
                 style='Dialog.TLabel').pack(pady=10)
        
        # Service name
        ttk.Label(dialog, 
                 text="Service Name:",
                 style='Dialog.TLabel').pack(pady=5)
        service_var = tk.StringVar()
        service_entry = ttk.Entry(dialog, 
                                 textvariable=service_var,
                                 font=('Arial', 11))
        service_entry.pack(pady=5)
        
        # Username
        ttk.Label(dialog, 
                 text="Username:",
                 style='Dialog.TLabel').pack(pady=5)
        username_var = tk.StringVar()
        username_entry = ttk.Entry(dialog, 
                                  textvariable=username_var,
                                  font=('Arial', 11))
        username_entry.pack(pady=5)
        
        # Password
        ttk.Label(dialog, 
                 text="Password:",
                 style='Dialog.TLabel').pack(pady=5)
        password_var = tk.StringVar()
        password_entry = ttk.Entry(dialog, 
                                  textvariable=password_var,
                                  show='*',
                                  font=('Arial', 11))
        password_entry.pack(pady=5)
        
        def submit():
            service = service_var.get().strip().lower()
            username = username_var.get().strip()
            password = password_var.get()
            
            if not all([service, username, password]):
                messagebox.showerror("Error", "All fields are required!")
                return
            
            self.add_password(service, username, password)
            self.update_services_list()
            self.status_var.set(f"Added password for {service}")
            dialog.destroy()
        
        # Create a frame for the button
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=20)
        
        submit_button = ttk.Button(button_frame, 
                                  text="Add Password", 
                                  command=submit,
                                  style='Dialog.TButton')
        submit_button.pack()
        
        # Set focus to the first entry field
        service_entry.focus()
    
    def view_password_dialog(self):
        """Dialog for viewing a password"""
        if not self.vault_data.get('services'):
            messagebox.showinfo("Info", "No services stored yet.")
            return
        
        service = simpledialog.askstring("View Password", 
                                        "Enter service name:",
                                        parent=self.root)
        if service:
            self.view_password(service.lower())
    
    def view_password(self, service):
        """View password for a specific service"""
        if service not in self.vault_data.get('services', {}):
            messagebox.showerror("Error", f"No entry found for service: {service}")
            return
        
        try:
            encrypted_data = self.vault_data['services'][service]
            decrypted_data = self.decrypt_data(encrypted_data, self.key)
            username, password = decrypted_data.split('|')
            
            # Show in a messagebox
            message = f"Service: {service.upper()}\nUsername: {username}\nPassword: {password}"
            messagebox.showinfo("Credentials", message)
            self.status_var.set(f"Viewed credentials for {service}")
            
        except Exception as e:
            if "decryption failed" in str(e).lower():
                messagebox.showerror("Security Error", 
                                    "Decryption failed! Master password may be incorrect.")
            else:
                messagebox.showerror("Error", f"Failed to decrypt: {str(e)}")
    
    def list_services(self):
        """Show list of all services"""
        services = list(self.vault_data.get('services', {}).keys())
        if not services:
            messagebox.showinfo("Info", "Your vault is empty.")
            return
        
        message = f"Services in your vault ({len(services)}):\n\n" + "\n".join(sorted(services))
        messagebox.showinfo("Your Services", message)
        self.status_var.set("Listed all services")
    
    def check_vault(self):
        """Check vault integrity"""
        if not self.vault_data.get('services'):
            messagebox.showinfo("Info", "Vault is empty.")
            return
        
        successful = 0
        failed = 0
        
        for service in self.vault_data['services']:
            try:
                encrypted_data = self.vault_data['services'][service]
                self.decrypt_data(encrypted_data, self.key)
                successful += 1
            except:
                failed += 1
        
        if failed == 0:
            messagebox.showinfo("Vault Check", 
                               f"✅ Vault integrity verified!\n{successful} entries are valid.")
        else:
            messagebox.showwarning("Vault Check", 
                                  f"⚠️ Vault check completed with errors!\n\n"
                                  f"Successful: {successful}\n"
                                  f"Failed: {failed}\n\n"
                                  "This may indicate:\n"
                                  "• Incorrect master password\n"
                                  "• Corrupted vault data")
        
        self.status_var.set(f"Vault check: {successful} OK, {failed} failed")
    
    # Cryptographic functions
    def derive_key(self, master_password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=ITERATIONS,
        )
        key = kdf.derive(master_password.encode())
        return key, salt

    def encrypt_data(self, plaintext: str, key: bytes) -> dict:
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8')
        }

    def decrypt_data(self, encrypted_data: dict, key: bytes) -> str:
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')

    def load_vault_metadata(self) -> dict:
        try:
            with open(DATA_FILE, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save_vault_metadata(self, data: dict):
        with open(DATA_FILE, 'w') as f:
            json.dump(data, f, indent=2)

    def add_password(self, service: str, username: str, password: str):
        credential_data = f"{username}|{password}"
        encrypted_credential = self.encrypt_data(credential_data, self.key)
        
        if 'services' not in self.vault_data:
            self.vault_data['services'] = {}
        
        self.vault_data['services'][service] = encrypted_credential
        self.save_vault_metadata(self.vault_data)

def main():
    """Main function to start the GUI application"""
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()