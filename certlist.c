/*============================================================================
#                             COMP30023 Assignment 2                         #
#                           TLS X509 certificate checker                     #
#      FileName: certlist.c                                                  #
#       Purpose: Certificate list functions                                  #
#        Author: Armaan McLeod                                               #
#         Email: dhaliwala@student.unimelb.edu.au                            #
# StudentNumber: 837674                                                      #
#      UserName: dhaliwala                                                   #
============================================================================*/

#include "certlist.h"

// Create linked list of certificates
list_t *initialise_certificates() {
    list_t *certificates = NULL;

    // Create certificates structure
    certificates = malloc(sizeof(*certificates));
    if (certificates == NULL) {
        free(certificates);
        fprintf(stderr, "Error: cannot malloc() linked list\n");
        exit(EXIT_FAILURE);
    }

    // Initialise the head and tail
    certificates->head = NULL;
    certificates->tail = NULL;

    return certificates;
}

// Add certificate to end of linked list
void add_certificate(list_t *certificates, certificate_t *info) {
    node_t *newnode = NULL;

    // Create a new node
    newnode = malloc(sizeof(*newnode));
    if (newnode == NULL) {
        free(newnode);
        fprintf(stderr, "Cannot malloc() new node\n");
        exit(EXIT_FAILURE);
    }

    // Copy over data to node
    newnode->info = info;
    newnode->next = NULL;

    // If end is empty, add to head
    if (certificates->tail == NULL) {
        certificates->head = newnode;
        certificates->tail = newnode;

    // Otherwise add to tail
    } else {
        certificates->tail->next = newnode;
        certificates->tail = newnode;
    }
}

// Free all certificate information stored
void free_certificates(list_t *certificates) {
    node_t *curr = certificates->head, *prev = NULL;

    while (curr != NULL) {
        prev = curr;
        curr = curr->next;
        free(prev->info->path);
        free(prev->info->hostname);
        free(prev->info);
        free(prev);
    }
    free(certificates);
}
