import ctypes
import struct

def check_dll_architecture(dll_path):
    with open(dll_path, 'rb') as f:
        dos_header = f.read(2)
        if dos_header != b'MZ':
            return "Not a valid DLL/EXE"

        # Move to PE header offset
        f.seek(60)
        pe_offset = struct.unpack('<I', f.read(4))[0]
        f.seek(pe_offset)
        
        # Check PE signature
        pe_signature = f.read(4)
        if pe_signature != b'PE\0\0':
            return "Invalid PE header"
        
        # Read Machine field
        machine = struct.unpack('<H', f.read(2))[0]
        
        if machine == 0x8664:
            return "64-bit (x64)"
        elif machine == 0x14C:
            return "32-bit (x86)"
        else:
            return f"Unknown architecture (Machine code: {hex(machine)})"

print(check_dll_architecture(r"C:\\Program Files\\GmSSL\\bin\\gmssl.dll"))