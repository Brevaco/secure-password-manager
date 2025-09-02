# password_manager.py
"""
SECURE PASSWORD MANAGER
BCA Final Year Project (Cloud and Security)
Amity University Online

This application provides a secure vault for storing and managing passwords.
It uses AES-256-GCM encryption for confidentiality and integrity, and PBKDF2HMAC
for deriving a secure key from the master password.
"""

import json
import base64
import os
import argparse
from getpass import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constants
DATA_FILE = "vault.dat"
ITERATIONS = 480000  # High iteration count to slow down brute-force attacks

def derive_key(master_password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """
    Derives a secure encryption key from the master password using PBKDF2.
    
    Args:
        master_password (str): The user's master password.
        salt (bytes, optional): The salt to use. If None, a new salt is generated.
        
    Returns:
        tuple[bytes, bytes]: The derived key and the salt used.
    """
    if salt is None:
        salt = os.urandom(16)  # Generate 16 random bytes for salt
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits for AES-256
        salt=salt,
        iterations=ITERATIONS,
    )
    key = kdf.derive(master_password.encode())
    return key, salt

def encrypt_data(plaintext: str, key: bytes) -> dict:
    """
    Encrypts a plaintext string using AES-GCM mode.
    
    Args:
        plaintext (str): The sensitive data to encrypt.
        key (bytes): The cryptographic key.
        
    Returns:
        dict: Dictionary containing 'ciphertext' and 'nonce' (both base64 encoded).
    """
    nonce = os.urandom(12)  # GCM recommends a 12-byte nonce
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return {
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8')
    }

def decrypt_data(encrypted_data: dict, key: bytes) -> str:
    """
    Decrypts ciphertext using AES-GCM mode.
    
    Args:
        encrypted_data (dict): Dictionary with 'ciphertext' and 'nonce'.
        key (bytes): The cryptographic key.
        
    Returns:
        str: The decrypted plaintext.
        
    Raises:
        Exception: If decryption fails (invalid key or corrupted data).
    """
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    nonce = base64.b64decode(encrypted_data['nonce'])
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')

def load_vault_metadata() -> dict:
    """
    Loads the vault metadata from file if it exists.
    
    Returns:
        dict: The vault metadata or empty dict if file doesn't exist.
    """
    try:
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_vault_metadata(data: dict):
    """
    Saves the vault metadata to file.
    
    Args:
        data (dict): The vault data to save.
    """
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def add_password(service: str, username: str, password: str, key: bytes, salt: bytes):
    """
    Adds a new password entry to the vault.
    
    Args:
        service (str): The service name (e.g., 'github').
        username (str): The username for the service.
        password (str): The password for the service.
        key (bytes): The encryption key.
        salt (bytes): The salt used for key derivation.
    """
    vault_data = load_vault_metadata()
    
    # Encrypt the credential data (username|password)
    credential_data = f"{username}|{password}"
    encrypted_credential = encrypt_data(credential_data, key)
    
    # Store the encrypted credential and salt
    if 'services' not in vault_data:
        vault_data['services'] = {}
    if 'vault_salt' not in vault_data:
        vault_data['vault_salt'] = base64.b64encode(salt).decode('utf-8')
    
    vault_data['services'][service] = encrypted_credential
    save_vault_metadata(vault_data)

def get_password(service: str, key: bytes):
    """
    Retrieves and decrypts a password from the vault.
    
    Args:
        service (str): The service name to retrieve.
        key (bytes): The encryption key.
    """
    vault_data = load_vault_metadata()
    
    if 'services' not in vault_data or service not in vault_data['services']:
        print(f"[ERROR] No entry found for service: {service}")
        return
    
    try:
        encrypted_data = vault_data['services'][service]
        decrypted_data = decrypt_data(encrypted_data, key)
        username, password = decrypted_data.split('|')
        
        print(f"\n🔓 Credentials for: {service.upper()}")
        print("-" * 30)
        print(f"👤 Username: {username}")
        print(f"🔑 Password: {password}")
        print("-" * 30)
        
    except Exception as e:
        # Check for the specific cryptography exception for invalid tags (failed decryption)
        if "decryption failed" in str(e).lower() or "tag" in str(e).lower():
            print(f"[SECURITY ALERT] Failed to decrypt data for '{service}'.")
            print("This almost always means the Master Password is incorrect.")
        else:
            print(f"[ERROR] An unexpected problem occurred: {e}")

def list_services():
    """
    Lists all services stored in the vault without decrypting them.
    """
    vault_data = load_vault_metadata()
    
    if 'services' not in vault_data or not vault_data['services']:
        print("Your vault is empty.")
        return
    
    print("\nServices in your vault:")
    for service in sorted(vault_data['services'].keys()):
        print(f"  • {service}")
    print(f"\nTotal: {len(vault_data['services'])} service(s)")

def check_vault_integrity(key: bytes):
    """
    Attempts to decrypt all entries to verify vault integrity.
    
    Args:
        key (bytes): The encryption key.
    """
    vault_data = load_vault_metadata()
    
    if 'services' not in vault_data or not vault_data['services']:
        print("[INFO] Vault is empty.")
        return True
    
    successful_decrypts = 0
    failed_decrypts = 0
    
    print("Checking vault integrity...")
    for service in vault_data['services']:
        try:
            encrypted_data = vault_data['services'][service]
            decrypted_data = decrypt_data(encrypted_data, key)
            username, password = decrypted_data.split('|')
            successful_decrypts += 1
            print(f"  ✓ {service}: OK")
        except Exception as e:
            failed_decrypts += 1
            print(f"  ✗ {service}: FAILED - {e}")
    
    print(f"\nIntegrity check results:")
    print(f"  Successful decryptions: {successful_decrypts}")
    print(f"  Failed decryptions: {failed_decrypts}")
    print(f"  Total entries: {successful_decrypts + failed_decrypts}")
    
    if failed_decrypts == 0:
        print("[SUCCESS] Vault integrity verified! All entries are valid.")
        return True
    else:
        print("[WARNING] Some entries could not be decrypted. This may indicate:")
        print("  • Incorrect master password")
        print("  • Corrupted vault data")
        return False

def show_help():
    """Displays detailed help information."""
    print("\n📖 PASSWORD MANAGER HELP")
    print("=" * 40)
    print("Usage: python password_manager.py <COMMAND> [SERVICE]")
    print("\nCommands:")
    print("  add <service>    - Add a new password for a service (e.g., 'github')")
    print("  get <service>    - Retrieve a password for a service")
    print("  list             - Show all services in your vault")
    print("  check            - Verify your vault's integrity and Master Password")
    print("  help             - Show this help message")
    print("\nExamples:")
    print("  python password_manager.py add github")
    print("  python password_manager.py get amazon")
    print("  python password_manager.py list")

def welcome_message():
    """Displays the application welcome message."""
    print("\n" + "="*55)
    print("       SECURE PASSWORD MANAGER - BCA PROJECT")
    print("="*55)
    print("🔐 AES-256-GCM Encryption | 🔑 PBKDF2 Key Derivation")
    print("="*55)

def main():
    """Main function to run the password manager."""
    welcome_message()
    
    parser = argparse.ArgumentParser(
        description='A secure password manager using AES-256 encryption',
        epilog='Example: python password_manager.py add github'
    )
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Add command
    parser_add = subparsers.add_parser('add', help='Add a new password')
    parser_add.add_argument('service', help='Service name (e.g., github, email)')
    
    # Get command
    parser_get = subparsers.add_parser('get', help='Get a password')
    parser_get.add_argument('service', help='Service name to retrieve')
    
    # List command
    subparsers.add_parser('list', help='List all saved services')
    
    # Check command
    subparsers.add_parser('check', help='Check vault integrity and master password')
    
    # Help command
    subparsers.add_parser('help', help='Show detailed help information')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        # Execute help command first without requiring password
        if args.command == 'help':
            show_help()
            return
            
        # For other commands, get master password securely
        master_pwd = getpass("Enter master password: ")
        if not master_pwd:
            print("[ERROR] Master password cannot be empty.")
            return
        
        # Load existing salt or create new one
        vault_data = load_vault_metadata()
        salt = base64.b64decode(vault_data.get('vault_salt', '')) if vault_data.get('vault_salt') else None
        
        # Derive key
        key, new_salt = derive_key(master_pwd, salt)
        
        # Store salt if this is a new vault
        if salt is None:
            vault_data['vault_salt'] = base64.b64encode(new_salt).decode('utf-8')
            save_vault_metadata(vault_data)
        
        # Execute command
        if args.command == 'add':
            username = input("Enter username: ").strip()
            if not username:
                print("[ERROR] Username cannot be empty.")
                return
            password = getpass("Enter password: ")
            if not password:
                print("[ERROR] Password cannot be empty.")
                return
            
            add_password(args.service.lower(), username, password, key, new_salt)
            print(f"[SUCCESS] Password for '{args.service}' added successfully!")
            
        elif args.command == 'get':
            get_password(args.service.lower(), key)
            
        elif args.command == 'list':
            list_services()
            
        elif args.command == 'check':
            check_vault_integrity(key)
            
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user. Exiting safely.")
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {e}")
        print("Please check your input and try again.")

if __name__ == "__main__":
    main()