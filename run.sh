#!/bin/bash

cyan=$(tput setaf 6)
normal=$(tput sgr0)
magenta=$(tput setaf 5)
yellow=$(tput setaf 3)

printf "${magenta}LOCAL TESTS${normal}\n"
printf "%0.s-" {1..120}
printf "\n"

printf "${yellow}INSTALL COLORDIFF${normal}\n"
printf "%0.s-" {1..120}
printf "\n"
sudo apt install colordiff
printf "%0.s-" {1..120}
printf "\n"
chmod +x ./test.sh
./test.sh

printf "\n${magenta}NECTAR TESTS${normal}\n"
printf "%0.s-" {1..120}
printf "\n${yellow}COPYING AND RUNNING FILES${normal}\n"
printf "${yellow}INSTALL COLORDIFF${normal}\n"
printf "%0.s-" {1..120}
printf "\n"
make scp
ssh -t uni "cd comp30023/Assignment2 && chmod +x ./test.sh && sudo apt install colordiff && ./test.sh"
