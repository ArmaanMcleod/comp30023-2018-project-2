#ifndef CERT_H
#define CERT_H

#include <stdio.h>
#include <stdlib.h>

// Certificate information stored here
typedef struct {
    char *path;
    char *url;
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

list_t *initialise_certificates();

void add_certificate(list_t *certificates, certificate_t *info);

void free_certificates(list_t *certificates);

#endif
