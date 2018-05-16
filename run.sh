#!/bin/bash

echo "Testing..."

make
valgrind --leak-check=full ./certcheck ./sample_certs/sample_input.csv
make clean

if diff ./output.csv ./sample_certs/sample_output.csv
then
    echo "Output Correct"
else
    echo "Output Incorrect"
fi
