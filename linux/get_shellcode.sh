#!/bin/bash
if [ $# -eq 2 ]
then
	filename=$1
	arch=$2
	python3 ./c2shellcode.py -d $filename $filename.s
	sed -i 's/#.*$//;/^$/d' $filename.s
	pwn asm -c $arch -f raw -i $filename.s -o $filename.bin
	echo "Your hex shellcode: "
	if [[ $arch == *"64"* ]]
	then
		python3 encoder-x64.py $filename.bin
	else
		python2 x86AlphanumEncoder.py $filename.bin
	fi
	# Cleanup
	rm $filename.*
else
	echo "Usage: ./get_shellcode.sh <C filename> <Arch>"
	exit
fi
