#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define START_SIZE 5;
#define BUFFER_SIZE 1024

typedef struct {
    const char *path;
    const char *url;
} certificate_t;

typedef struct {
    certificate_t *info;
    size_t n;
} certificates_t;

certificates_t *initialise_certificates(size_t num_certificates) {
    certificates_t *certificates = NULL;

    // Create certificates structure
    certificates = malloc(sizeof(*certificates));
    if (!certificates) {
        fprintf(stderr, "Error: cannot malloc() certificates structure\n");
        exit(EXIT_FAILURE);
    }

    certificates->n = 0;

    // Allocate certificates array
    certificates->info = malloc(num_certificates *
                                sizeof(*(certificates->info)));
    if (!certificates->info) {
        fprintf(stderr, "Error: cannot malloc() %zu certificates\n",
                         num_certificates);
        exit(EXIT_FAILURE);
    }

    return certificates;
}

certificates_t *read_input_csv(const char *csv_path) {
    FILE *stream = NULL;
    char buffer[BUFFER_SIZE] = {0};
    char *temp = NULL, *path = NULL, *url = NULL, *saveptr = NULL;
    certificates_t *certificates = NULL;
    size_t slen, num_certificates = START_SIZE;
    const char *delim = " ,";

    // Initialise certificates
    certificates = initialise_certificates(num_certificates);

    // Open csv file
    stream = fopen(csv_path, "r");
    if (!stream) {
        fprintf(stderr, "Failed to open file\n");
        exit(EXIT_FAILURE);
    }

    // Read through each line
    while (fgets(buffer, sizeof buffer, stream) != NULL) {

        // Resize certificates array if lines exceed maximum
        if (certificates->n == num_certificates) {
            num_certificates *= 2;
            certificates->info = realloc(certificates->info,
                            num_certificates * sizeof(*(certificates->info)));
            if (!certificates) {
                fprintf(stderr, "Error: realloc() failed to resize buffer to"
                                 "%zu bytes\n", num_certificates);
                exit(EXIT_FAILURE);
            }
        }

        slen = strlen(buffer);

        // Remove trailing newline character
        if (slen > 0 && buffer[slen-1] == '\n') {
            buffer[slen-1] = '\0';
        }

        // copy buffer
        temp = strdup(buffer);
        if (!temp) {
            fprintf(stderr, "Error: strdup() failed to copy buffer\n");
            exit(EXIT_FAILURE);
        }

        // Extract path
        path = strtok_r(temp, delim, &saveptr);
        certificates->info[certificates->n].path = strdup(path);
        if (!certificates->info[certificates->n].path) {
            fprintf(stderr, "Error: stdup() can't parse path\n");
            exit(EXIT_FAILURE);
        }

        // Extract url
        url = strtok_r(NULL, delim, &saveptr);
        certificates->info[certificates->n].url = strdup(url);
        if (!certificates->info[certificates->n].url) {
            fprintf(stderr, "Error: strdup() can't parse url\n");
            exit(EXIT_FAILURE);
        }

        certificates->n++;
    }

    return certificates;
}

char *get_certificate_path(const char *csv_path) {
    char *path = strdup(csv_path);
    char *path_to_certificates = NULL;
    const char separator = '/';

    // Split apath on last slash
    char *split_at = strrchr(path, separator);

    // If slash found, split and create current directory path
    if(split_at != NULL) {
        *split_at = '\0';

         path_to_certificates = malloc(strlen(path) + 2);
         memset(path_to_certificates, '\0', strlen(path) + 2);
         strcpy(path_to_certificates, path);
         strcat(path_to_certificates, "/");

    // If not slash found, must be current directory
    } else {
        path_to_certificates = "./";
    }

    free(path);

    return path_to_certificates;
}

void verify_certificate(const char *cert_path) {
    BIO *cert_bio = NULL;
    X509 *cert = NULL;
    X509_NAME *cert_issuer = NULL;
    X509_CINF *cert_info = NULL;
    STACK_OF(X509_EXTENSION) * extension_list;
    int read_cert_bio;

    // Initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    // Create BIO object to read certificate
    cert_bio = BIO_NEW(BIO_s_file());

    // Read certificate into BIO
    read_cert_bio = BIO_read_filename(cert_bio, cert_path);
    if (!read_cert_bio) {
        fprintf(stderr, "Error in reading cert BIO filename\n");
        exit(EXIT_FAILURE);
    }

    // Load certificate into bio

    return;
}

int main(int argc, char *argv[]) {
    certificates_t *certificates = NULL;
    char *path_to_certificates = NULL;

    if (argc != 2) {
        fprintf(stderr, "Usage: ./certcheck [relative path to csv file]\n");
        exit(EXIT_FAILURE);
    }

    certificates = read_input_csv(argv[1]);

    for (size_t i = 0; i < certificates->n; i++) {
        printf("%s,%s\n",
        certificates->info[i].path,
        certificates->info[i].url);
    }

    path_to_certificates = get_certificate_path(argv[1]);

    printf("%s\n", path_to_certificates);

    exit(EXIT_SUCCESS);
}
