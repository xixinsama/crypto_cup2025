import binascii
from gmssl import sm3, func
from Crypto.Util.number import *

counter = 0x7501e6ea
token = 0xf4ce927c79b616e8e8f7223828794eedf9b16591ae572172572d51e135e0d21a

counter_new = bytes.fromhex(hex(counter)[2:]) 
counter_new += b'\x80' + b'\x00' * 19    # padding
counter_new += b'\x00' * 6 + b'\x01\x20' # len
counter_new += b'\xff' * 4               # counter_append
last_block = b'\xff' * 4
last_block += b'\x80' + b'\x00' * 51     # padding
last_block += b'\x00' * 6 + b'\x02\x20'  # len

prefHashValue = bytes.fromhex(hex(token)[2:])
prefHashValue = [bytes_to_long(prefHashValue[i:i+4]) for i in range(0, 32, 4)]
NewHashValue = sm3.sm3_cf(prefHashValue, func.bytes_to_list(last_block))
NewHashValue = ''.join(['%08x'%val for val in NewHashValue])

print('counter:', counter_new.hex())
print('token:', NewHashValue)

print(counter_new)