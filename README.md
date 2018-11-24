# COMP30023 Assignment 2

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This repository contains Assignment 2 for COMP30023 Computer Systems Semester 1 2018. The aim of this project was to create a TLS certifcate checker that checks X509 certificates.

## Files
* **testscript.sh** shell script provided by Chris for testing
* **test.sh/run.sh** personal shell script files
* **certcheck.c** main program.
* **verify.c/verify.h** modules providing verification of certificates.
* **filehandle.c/filehandle.h** modules providing reading and writing of certificate data and results.
* **cerlist.c/certlist.h** linked list modules for storing certificates.
* **host.c/host.h** host validation modules.

## Running test script
Make sure that the **testscript.sh** is executable then run:

./testscript.sh

## Running
Make sure you compile the server with either *make* or *make certcheck*, then run:

./certcheck *input_csv*

For example:

./certcheck input.csv

Feel free to try it out.
