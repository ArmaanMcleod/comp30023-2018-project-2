#!/bin/bash


# make the project
make
./certcheck ./sample_certs/sample_input.csv
make clean

green=$(tput setaf 2)
red=$(tput setaf 1)
normal=$(tput sgr0)

printf "%0.s-" {1..120}
printf "\nRESULT\n"
printf "%0.s-" {1..120}
printf "\n"

# check output matches sample output
out1="./output.csv"
out2="./sample_certs/sample_output.csv"
difference="$(colordiff -y -N "$out1" "$out2")"
if [ -n "$difference" ]; then
    printf "${red}FAILED${normal}\nDIFFERENCES HIGHLIGHTED BELOW\n\n$difference\n"
else
    printf "${green}PASSED\n"
fi

printf "%0.s-" {1..120}
printf "\n"
