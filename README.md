# CryptICE
ICE cipher for Python

# Installation
```bash
python3 -m pip install --upgrade CryptICE
```

# Example
```python
from CryptICE import IceKey

data = b'Hello, World!'
key = bytearray([ 0x25, 0x6C, 0xC7, 0x0A, 0x00, 0x30, 0x00, 0x5C ])

ice = IceKey(1, key)

encrypted_data = ice.Encrypt(data, True) # The last argument activates "CMS Padding" (Default is False)
print(f'Encrypted = {encrypted_data}') # b'\x12*\xe2\x199\xe7,\x949?\x99\x0e\x96\x88\x84>'
print(f'Decrypted = {ice.Decrypt(encrypted_data)}') # b'Hello, World!\x03\x03\x03'
print(f'Decrypted = {ice.Decrypt(encrypted_data, True)}') # b'Hello, World!'

```
