#!/bin/bash
if [ $# -eq 1 ]
then
	filename=$1
	python3 ./c2shellcode.py -d $filename $filename.s
	sed -i 's/#.*$//;/^$/d' $filename.s
	pwn asm -c amd64 -f raw -i $filename.s -o $filename.bin
	echo "Your hex shellcode: "
	python3 encoder-x64.py $filename.bin
	# Cleanup
	rm $filename.*
else
	echo "Usage: ./get_shellcode.sh <C filename>"
	exit
fi
