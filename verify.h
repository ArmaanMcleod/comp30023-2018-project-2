#ifndef VERIFY_H
#define VERIFY_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define MIN_RSA_LENGTH 2048
#define EXT_BUFFER_SIZE 1024
#define VALID_EXTENSIONS

#define ARRAY_LENGTH(x) (sizeof x / sizeof *x)

typedef enum {
    SAN_NOT_PRESENT = -1,
    SAN_NOT_FOUND = 0,
    SAN_FOUND = 1
} san_t;

typedef enum {
    CN_NOT_PRESENT = -1,
    CN_NOT_FOUND = 0,
    CN_FOUND = 1
} common_t;

typedef enum {
    EXTENSION_NOT_PRESENT = -1,
    EXTENSION_NOT_FOUND = 0,
    EXTENSION_FOUND = 1
} ext_t;

typedef enum {
    TIME_SOONER = -1,
    TIME_LATER = 1,
    TIME_SAME = 0
} time_type_t;

typedef enum {
    KEY_SHORTER,
    KEY_CORRECT
} key_length_t;

extern const char *CONSTRAINT_NAME;
extern const char *CONSTRAINT_VALUE;
extern const char *EXTENDED_KEY_NAME;
extern const char *ENHANCED_KEY_NAME;
extern const char *KEY_VALUE;

int verify_certificate(const char *cert_path, const char *url);

#endif
