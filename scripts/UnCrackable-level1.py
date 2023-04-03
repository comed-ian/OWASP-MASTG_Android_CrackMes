from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import binascii
        
key = b"8d127684cbc37c17616d806cf50473cc"
key = binascii.unhexlify(key)
secret = base64.b64decode(b"5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=")
aes = AES.new(key, AES.MODE_ECB)
c = aes.decrypt(secret)
print("password: " + unpad(c, 16).decode())
