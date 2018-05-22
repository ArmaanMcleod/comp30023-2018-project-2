/*============================================================================
#                             COMP30023 Assignment 2                         #
#                           TLS X509 certificate checker                     #
#      FileName: certlist.h                                                  #
#       Purpose: Header file for certlist.c                                  #
#        Author: Armaan Dhaliwal-McLeod                                      #
#         Email: dhaliwala@student.unimelb.edu.au                            #
# StudentNumber: 837674                                                      #
#      UserName: dhaliwala                                                   #
============================================================================*/

#ifndef CERT_H
#define CERT_H

#include <stdio.h>
#include <stdlib.h>

// Certificate information stored here
typedef struct {
    char *path;
    char *hostname;
} certificate_t;

// Certifcate node
typedef struct node {
    certificate_t *info;
    struct node *next;
} node_t;

// Certificate list
typedef struct {
    node_t *head;
    node_t *tail;
} list_t;

// Function prototypes
list_t *initialise_certificates();

void add_certificate(list_t *certificates, certificate_t *info);

void free_certificates(list_t *certificates);

#endif
