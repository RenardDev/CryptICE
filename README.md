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

ice = IceKey(0, [ 0x45, 0x32, 0x4E, 0x63, 0x55, 0x6B, 0x47, 0x32 ]) # 64 bit key used

encrypted_data = ice.Encrypt(data)
print(f'Encrypted = {encrypted_data}') # b'@\xff\xf3TQ>X\x04orld!'
print(f'Decrypted = {ice.Decrypt(encrypted_data)}') # b'Hello, World!'

```
