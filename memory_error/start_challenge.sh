#!/bin/zsh
if [ -z "$1" ]; then
    echo "Error: No argument supplied"
    exit 1
fi

mkdir -p $1
cd $1
scp -r pwncollege:/challenge/. ./

for file in ./*; do
    if [[ $file != *.c ]]; then
        # Run your command on the file
        pwn template $file > solve.py
        ida64 $file & disown
        #auto_ghidra $file
        break
    fi
done
