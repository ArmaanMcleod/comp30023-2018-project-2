#!/bin/bash


# make the project
make
make run
make clean

# create colours
green=$(tput setaf 2)
red=$(tput setaf 1)
normal=$(tput sgr0)

printf "%0.s-" {1..120}
printf "\nRESULT\n"
printf "%0.s-" {1..120}
printf "\n"

# check output matches sample output
out1=./output.csv
out2=./sample_certs/sample_output.csv
if colordiff -y -N --color=always $out1 $out2 > temp
then
    printf "${green}PASSED${normal}\n"
else
    printf "${red}FAILED${normal}\nDIFFERENCES HIGHLIGHTED BELOW\n\n"
    contents="$(cat "temp"; printf x)"
    contents="${contents%x}"
    printf "%s" "$contents"
fi

printf "%0.s-" {1..120}
printf "\n"

# remove temp
rm temp
