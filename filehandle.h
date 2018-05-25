/*============================================================================
#                             COMP30023 Assignment 2                         #
#                           TLS X509 certificate checker                     #
#      FileName: filehandle.h                                                #
#       Purpose: Header file for filehandle.c                                #
#        Author: Armaan Dhaliwal-McLeod                                      #
#         Email: dhaliwala@student.unimelb.edu.au                            #
# StudentNumber: 837674                                                      #
#      UserName: dhaliwala                                                   #
============================================================================*/

#ifndef FILE_H
#define FILE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "certlist.h"

#define BUFFER_SIZE 1024

// Function prototypes
list_t *read_input_csv(const char *csv_path);

void write_results(const char *filename, list_t *certificates);

#endif
