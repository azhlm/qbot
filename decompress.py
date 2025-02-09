from ctypes import *
import binascii
import zlib
import struct
import sys

brieflz = cdll.LoadLibrary('./brieflz.dll')


DEFAULT_BLOCK_SIZE = 1024 * 1024

### Code from sysopfb 
### https://github.com/sysopfb/Malware_Scripts/blob/master/qakbot/blzpack.py
def decompress_data(data, blocksize=DEFAULT_BLOCK_SIZE, level=1):
	decompressed_data = b""
	max_packed_size = brieflz.blz_max_packed_size(blocksize)
	
	(magic,level,packedsize,crc,hdr_depackedsize,crc2) = struct.unpack_from('>IIIIII', data)
	data = data[24:]
	while magic == 0x626C7A1A and len(data) > 0:
		compressed_data = create_string_buffer(data[:packedsize])
		workdata = create_string_buffer(blocksize)
		depackedsize = brieflz.blz_depack(byref(compressed_data), byref(workdata), c_int(hdr_depackedsize))
		if depackedsize != hdr_depackedsize:
			print("[!] Decompression error")
			print("[!] DepackedSize: "+str(depackedsize) + "\nHdrVal: "+str(hdr_depackedsize))
			return None
		decompressed_data += workdata.raw[:depackedsize]
		data = data[packedsize:]
		if len(data) > 0:
			(magic,level,packedsize,crc,hdr_depackedsize,crc2) = struct.unpack_from('>IIIIII', data)
			data = data[24:]
		else:
			break
	return decompressed_data

def main():
    if len(sys.argv) != 2:
        print(f"[!] Usage: {sys.argv[0]} <compressed_file>")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        data = f.read()
        print(f"[+] Read data from file {sys.argv[1]} with size {len(data)} bytes")
    # Fix the magic number
    data = data.replace(b"\x61\x6c\xd3\x1a", b"\x62\x6C\x7A\x1A")
    print("[+] Decompressing data...")
    decompressed_data = decompress_data(data)
    print(f"[+] Successfully decompressed data : {decompressed_data[:20]}")
	
    with open("decompressed.bin", "wb") as f:
        f.write(decompressed_data)
        print("[+] Decompressed data written to decompressed.bin")
	
if __name__ == "__main__":
    main()