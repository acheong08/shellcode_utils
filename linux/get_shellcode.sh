#!/bin/bash
if [ $# -eq 2 ]
then
	filename=$1
	arch=$2
	python3 ./c2shellcode.py -d $filename $filename.s
	sed -i 's/#.*$//;/^$/d' $filename.s
	pwn asm -c $arch -f raw -i $filename.s -o $filename.bin
	echo "Your hex shellcode: "
	python3 encoder-x64.py $filename.bin
	# Cleanup
	rm $filename.*
else
	echo "Usage: ./get_shellcode.sh <C filename> <Arch>"
	exit
fi
