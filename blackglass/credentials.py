"""Local credential storage (XOR-obfuscated profile file)."""

import base64
import json
import os


_SECRET_KEY = b"sl_chat_key_v1"
CREDENTIALS_FILE = "sl_credentials.json"

def _cipher_xor(data_bytes, key=_SECRET_KEY):
    """Simple repeating-key XOR cipher."""
    key_len = len(key)
    return bytes(data_bytes[i] ^ key[i % key_len] for i in range(len(data_bytes)))

def save_credentials(credentials):
    """Saves a single credential entry to the JSON file, encrypting the password."""
    try:
        if os.path.exists(CREDENTIALS_FILE):
            with open(CREDENTIALS_FILE, 'r') as f:
                data = json.load(f)
        else:
            data = []
            
        full_name = f"{credentials['first']} {credentials['last']}"
        existing_names = [f"{c['first']} {c['last']}" for c in data]

        if full_name in existing_names:
            index = existing_names.index(full_name)
            data.pop(index) 
        
        password_bytes = credentials['password'].encode('utf-8')
        encrypted_password = _cipher_xor(password_bytes)
        
        encoded_password = base64.b64encode(encrypted_password).decode('utf-8')
        
        new_entry = {
            'first': credentials['first'],
            'last': credentials['last'],
            'password_enc': encoded_password,
            'region': credentials['region']
        }
        data.append(new_entry)

        with open(CREDENTIALS_FILE, 'w') as f:
            json.dump(data, f, indent=4)
            
        return True
    except Exception:
#         print(f"Error saving credentials: {e}")
        return False

def load_credentials():
    """Loads all credentials from the JSON file, decrypting passwords."""
    if not os.path.exists(CREDENTIALS_FILE):
        return []
    
    try:
        with open(CREDENTIALS_FILE, 'r') as f:
            data = json.load(f)
            
        decrypted_data = []
        for entry in data:
            try:
                encoded_password = entry.get('password_enc', '')
                if not encoded_password: continue
                
                encrypted_password = base64.b64decode(encoded_password)
                password_bytes = _cipher_xor(encrypted_password)
                password = password_bytes.decode('utf-8')
                
                decrypted_data.append({
                    'first': entry['first'],
                    'last': entry['last'],
                    'password': password,
                    'region': entry.get('region', 'last') 
                })
            except Exception as e:
                print(f"Warning: Failed to decrypt credential entry. Skipping. Error: {e}")
                continue
                
        return decrypted_data
    except Exception:
#         print(f"Error loading credentials (file corrupted?): {e}")
        return []

