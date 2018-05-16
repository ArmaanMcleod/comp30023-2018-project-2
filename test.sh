#!/bin/bash

# make the project
make
valgrind --leak-check=full ./certcheck ./sample_certs/sample_input.csv

# check output matches sample output
out1="./output.csv"
out2="./sample_certs/sample_output.csv"
difference="$(diff -q "$out1" "$out2")"
if [ -n "$difference" ]; then
    printf "FAILED\n$difference\n" > result
else
    printf "PASSED\n" > result
fi

make clean
