#!/bin/bash

printf "LOCAL TESTS\n"
printf "%0.s-" {1..80}
printf "\n"
chmod +x test.sh
./test.sh

printf "\nRESULT\n"
printf "%0.s-" {1..80}
printf "\n"
cat result
printf "%0.s-" {1..80}
printf "\n"

printf "\nNECTAR TESTS\n"
printf "%0.s-" {1..80}
printf "\n"
make scp
ssh -t uni "cd comp30023/Assignment2 && chmod +x test.sh && ./test.sh"

printf "\nRESULT\n"
printf "%0.s-" {1..80}
printf "\n"
cat result
printf "%0.s-" {1..80}
printf "\n"
