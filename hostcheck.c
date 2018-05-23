/*============================================================================
#                             COMP30023 Assignment 2                         #
#                           TLS X509 certificate checker                     #
#      FileName: hostcheck.c                                                 #
#       Purpose: Checks if hostname matches given name                       #
#        Author: Armaan Dhaliwal-McLeod                                      #
#         Email: dhaliwala@student.unimelb.edu.au                            #
# StudentNumber: 837674                                                      #
#      UserName: dhaliwala                                                   #
============================================================================*/

#include "hostcheck.h"

// Compare sub domains between name and host
static int check_sub_domain(const char *name, const char *hostname) {
    const char *delim = ".";
    char *name_copy = NULL, *hostname_copy = NULL;
    char *sub_domain_name = NULL, *sub_domain_hostname = NULL;
    char *saveptr = NULL;
    int result;

    // Create copies
    name_copy = strdup(name);
    hostname_copy = strdup(hostname);

    // Extract subdomain
    sub_domain_name = strtok_r(name_copy, delim, &saveptr);
    sub_domain_hostname = strtok_r(hostname_copy, delim, &saveptr);

    // Check sub domains, allowing wildcards to also be considered
    result = fnmatch(sub_domain_name, sub_domain_hostname,
                     FNM_CASEFOLD | FNM_EXTMATCH) == 0;

    free(name_copy);
    free(hostname_copy);

    return (result) ? DOMAIN_VALID : DOMAIN_INVALID;
}

// Compare domains between name and host
static int check_domain(const char *name, const char *hostname) {
    char *name_copy = NULL, *hostname_copy = NULL;
    char *domain_name = NULL, *domain_hostname = NULL;
    const char delim = '.';
    int result;

    // Create copies
    name_copy = strdup(name);
    hostname_copy = strdup(hostname);

    // Extract domain
    domain_name = strchr(name_copy, delim);
    domain_hostname = strchr(hostname_copy, delim);

    // Compare domains
    result = strcasecmp(domain_name, domain_hostname) == 0;

    free(name_copy);
    free(hostname_copy);

    return (result) ? DOMAIN_VALID : DOMAIN_INVALID;
}

// Validates hostname against name
int validate_host(const char *name, const char *hostname) {
    return check_sub_domain(name, hostname) == DOMAIN_VALID &&
           check_domain(name, hostname) == DOMAIN_VALID;
}
