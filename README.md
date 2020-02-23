# CryptICE
ICE cipher for Python

# Example
```
from CryptICE import IceKey

data = [ 0x07, 0x92, 0x26, 0x74, 0x89, 0x42, 0x73, 0x61 ]
key = [ 0x25, 0x6C, 0xC7, 0x0A, 0x00, 0x30, 0x00, 0x5C ]

ice = IceKey(1, key)
en = ice.Encrypt(data)
de = ice.Decrypt(en)
print(f'Val = {bytes(data) == de}')

```
