#!/bin/zsh
if [ -z "$1" ]; then
    echo "Missing path to folder"
    exit 1
fi

if [ ! -d "$1" ]; then
    echo "$1 is not a directory"
    exit 1
fi

cd $1

if [ ! -f "solve.py" ]; then
    echo "solve.py not found in $1"
    exit 1
fi

challenge=`ssh pwncollege "ls /challenge/"`
ssh pwncollege "mkdir -p /tmp/solve_challenge/"
scp solve.py pwncollege:/tmp/solve_challenge/solve.py
ssh pwncollege "python /tmp/solve_challenge/solve.py EXE=/challenge/$challenge"