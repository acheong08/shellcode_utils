# shellcode_utils
One liners to convert C code to shellcode

# Usage
## Downloading
`$ git clone https://github.com/acheong08/shellcode_utils`
## Dependencies
`$ cd shellcode_utils/linux`

`$ ./requirements.sh`
## Running
`$ ./get_shellcode.sh <C file> <arch>`

Arch: choose from '16', '32', '64', 'android', 'baremetal', 'cgc', 'freebsd', 'linux', 'windows', 'powerpc64', 'aarch64', 'powerpc', 'sparc64', 'mips64', 'msp430', 'alpha', 'amd64', 'riscv', 'sparc', 'thumb', 'cris', 'i386', 'ia64', 'm68k', 'mips', 's390', 'none', 'avr', 'arm', 'vax', 'little', 'big', 'be', 'eb', 'le', 'el'

# Other notes
[Using the shellcode](linux/README.md)

# Credits
https://github.com/ebubekirtrkr/c2shellcode - For converting C to assembly

https://github.com/Gallopsled/pwntools - For getting raw opcodes from assembly

https://github.com/ColeHouston/x64-shellcode-encoder - For converting raw opcodes into string and fixing null bytes

https://github.com/isears/x86AlphanumEncoder - For x86 encoding
