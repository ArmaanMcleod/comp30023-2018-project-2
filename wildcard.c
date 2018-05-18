#include "wildcard.h"

// Get sub domain of pattern
static char *get_sub_domain(char *pattern) {
    const char *delim = ".";
    char *copy = strdup(pattern);
    char *saveptr = NULL;

    char *sub_domain = strtok_r(copy, delim, &saveptr);

    return sub_domain;
}

// Get domain of pattern
static char *get_domain(char *pattern) {
    const char delim = '.';

    char *domain = strchr(pattern, delim);

    return domain;
}

// Count how many dots exist
// A valid wildcard must have atlead 2 dots
static int check_length_wildcard(char *pattern) {
    const char delim = '.';
    int count = 0;

    for (size_t i = 0; pattern[i]; i++) {
        if (pattern[i] == delim) {
            count++;
        }
    }

    return (count + 1 > MIN_WILDCARD_LEN);
}

// Validate hostname with pattern
int validate_hostname(const char *pattern, const char *hostname) {
    int valid;
    char *wildcard_pattern, *pattern_sub = NULL, *hostname_sub = NULL;
    char *pattern_dom, *hostname_dom;
    const char wildcard = '*';
    char *pattern_copy = NULL, *host_copy = NULL;

    // Create copy of original pattern
    pattern_copy = strdup(pattern);
    if (pattern_copy == NULL) {
        fprintf(stderr, "Cannot strdup() copy of pattern\n");
        exit(EXIT_FAILURE);
    }


    // Create copy of original hostname
    host_copy = strdup(hostname);
    if (host_copy == NULL) {
        fprintf(stderr, "Cannot strdup() copy of hostname\n");
        exit(EXIT_FAILURE);
    }

    // Check if wildcard exists
    wildcard_pattern = strchr(pattern_copy, wildcard);

    // If no wildcard exists, compare strings normally
    if (wildcard_pattern == NULL) {
        valid = strcasecmp(pattern_copy, host_copy);
        free(pattern_copy);
        free(host_copy);
        return (valid == 0) ? WILDCARD_FOUND : WILDCARD_NOT_FOUND;
    }

    // Get sub domains
    pattern_sub = get_sub_domain(pattern_copy);
    hostname_sub = get_sub_domain(host_copy);

    // Get domains
    pattern_dom = get_domain(pattern_copy);
    hostname_dom = get_domain(host_copy);

    // If sub domain wildcard is valid
    // And domains match up
    // And length of wildcard pattern is valid
    valid = (fnmatch(pattern_sub, hostname_sub, FNM_CASEFOLD) == 0) &&
            (strcasecmp(pattern_dom, hostname_dom) == 0) &&
            (check_length_wildcard(pattern_copy));

    // Free up all pointers
    free(pattern_sub);
    free(hostname_sub);
    free(pattern_copy);
    free(host_copy);

    return (valid) ? WILDCARD_FOUND : WILDCARD_NOT_FOUND;
}
