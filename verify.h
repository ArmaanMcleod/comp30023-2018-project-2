/*============================================================================
#                             COMP30023 Assignment 2                         #
#                           TLS X509 certificate checker                     #
#      FileName: verify.h                                                    #
#       Purpose: Header file for verify.c                                    #
#        Author: Armaan Dhaliwal-McLeod                                      #
#         Email: dhaliwala@student.unimelb.edu.au                            #
# StudentNumber: 837674                                                      #
#      UserName: dhaliwala                                                   #
============================================================================*/

#ifndef VERIFY_H                                                             
#define VERIFY_H

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define MIN_RSA_LENGTH 2048
#define EXT_BUFFER_SIZE 1024

// Enum for SAN flags
typedef enum {
    SAN_NOT_PRESENT = -1,
    SAN_NOT_FOUND = 0,
    SAN_FOUND = 1
} san_t;

// Enum for CN flags
typedef enum {
    CN_NOT_PRESENT = -1,
    CN_NOT_FOUND = 0,
    CN_FOUND = 1
} common_t;

// Enum for extension flags
typedef enum {
    EXTENSION_ERROR = -1,
    EXTENSION_NOT_FOUND = 0,
    EXTENSION_FOUND = 1
} ext_t;

// Enum for time flags
typedef enum {
    TIME_SOONER = -1,
    TIME_LATER = 1,
    TIME_SAME = 0
} time_type_t;

// Enum for key flags
typedef enum {
    KEY_NOT_PRESENT = -1,
    KEY_SHORTER = 0,
    KEY_CORRECT = 1
} key_length_t;

// Function prototypes
int verify_certificate(const char *cert_path, const char *url);

#endif
