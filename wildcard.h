#ifndef WILDCARD_H
#define WILDCARD_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>

typedef enum {WILDCARD_NOT_FOUND, WILDCARD_FOUND, MIN_WILDCARD_LEN} wildcard_t;

int validate_hostname(const char *pattern, const char *hostname);

#endif
