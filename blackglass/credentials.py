"""Local credential storage.

On Windows the entire credential JSON is additionally sealed with DPAPI
(CryptProtectData, user scope) - the strongest storage available without
extra dependencies. Other platforms use per-password XOR obfuscation.
Files written by older versions are upgraded automatically on load.
"""

import base64
import json
import os
import sys


_SECRET_KEY = b"sl_chat_key_v1"
CREDENTIALS_FILE = "sl_credentials.json"
_DPAPI_MAGIC = b"DPAPI1:"


def _dpapi_protect(data):
    """Seal *data* (bytes) with CryptProtectData; returns DPAPI1:-prefixed blob."""
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    bin_blob = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(bin_blob), None, None, None, None, 0, ctypes.byref(out)):
        raise OSError("CryptProtectData failed")
    try:
        sealed = ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)
    return _DPAPI_MAGIC + base64.b64encode(sealed)


def _dpapi_unprotect(blob):
    """Open a DPAPI1:-prefixed blob; returns original bytes."""
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    raw = base64.b64decode(blob[len(_DPAPI_MAGIC):])
    buf = ctypes.create_string_buffer(raw, len(raw))
    bin_blob = DATA_BLOB(len(raw), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(bin_blob), None, None, None, None, 0, ctypes.byref(out)):
        raise OSError("CryptUnprotectData failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)

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

        payload = json.dumps(data, indent=4).encode("utf-8")
        if sys.platform == "win32":
            payload = _dpapi_protect(payload)

        with open(CREDENTIALS_FILE, "wb") as f:
            f.write(payload)
        if os.name == "posix":
            try:
                os.chmod(CREDENTIALS_FILE, 0o600)
            except Exception:
                pass

        return True
    except Exception:
#         print(f"Error saving credentials: {e}")
        return False

def load_credentials():
    """Loads all credentials from the JSON file, decrypting passwords."""
    if not os.path.exists(CREDENTIALS_FILE):
        return []
    
    try:
        with open(CREDENTIALS_FILE, "rb") as f:
            raw = f.read()
        if raw.startswith(_DPAPI_MAGIC):
            data = json.loads(_dpapi_unprotect(raw).decode("utf-8"))
        else:
            data = json.loads(raw.decode("utf-8"))
            
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

