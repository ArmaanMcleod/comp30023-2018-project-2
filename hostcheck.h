/*============================================================================
#                             COMP30023 Assignment 2                         #
#                           TLS X509 certificate checker                     #
#      FileName: hostcheck.h                                                 #
#       Purpose: Header for host.c                                           #
#        Author: Armaan Dhaliwal-McLeod                                      #
#         Email: dhaliwala@student.unimelb.edu.au                            #
# StudentNumber: 837674                                                      #
#      UserName: dhaliwala                                                   #
============================================================================*/

#ifndef HOST_H
#define HOST_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>

// Enum for host checking
typedef enum {
    HOST_INVALID,
    HOST_VALID
} host_t;

// Enum for domain checking
typedef enum {
    DOMAIN_INVALID,
    DOMAIN_VALID
} domain_t;

// Function prototypes
int validate_host(const char *name, const char *hostname);

#endif
