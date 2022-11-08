# Notes
Compiling C code with embedded shellcode:

`gcc <file.c> -o <output> -m64 -fno-stack-protector -z execstack`

Injecting shellcode:

https://github.com/secretsquirrel/the-backdoor-factory
