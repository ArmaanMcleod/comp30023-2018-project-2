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

#define FMATCH FNM_CASEFOLD

typedef enum {SAN_NOT_PRESENT = -1, SAN_NOT_FOUND = 0, SAN_FOUND = 1} san_t;
typedef enum EXT {EXTENSION_NOT_FOUND, EXTENSION_FOUND} extension_t;
typedef enum {TIME_SOONER = -1, TIME_LATER = 1, TIME_SAME = 0} time_type_t;
typedef enum {KEY_SHORTER, KEY_CORRECT} key_length_t;

extern const char *CONSTRAINT_NAME;
extern const char *CONSTRAINT_VALUE;
extern const char *EXTENDED_KEY_NAME;
extern const char *EXTENDED_KEY_VALUE;

int verify_certificate(const char *cert_path, const char *url);

#endif
