#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <fnmatch.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define START_SIZE 5;
#define BUFFER_SIZE 256
#define LARGE_BUFFER_SIZE 1024

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

// Check if date is valid
int check_date(ASN1_TIME *time_to) {
    int day, sec;

    // Not before
    if (!ASN1_TIME_diff(&day, &sec, NULL, time_to)) {
        fprintf(stderr, "Invalid time format\n");
        exit(EXIT_FAILURE);
    }

    // Later
    if (day > 0 || sec > 0) {
        return 1;

    // Sooner
    } else if (day < 0 || sec < 0) {
        return -1;
    }

    // Same
    return 0;
}

int validate_dates(X509 *cert) {
    ASN1_TIME *not_before = NULL, *not_after = NULL;
    int check_before, check_after;

    // Get time periods
    not_before = X509_get_notBefore(cert);
    not_after = X509_get_notAfter(cert);

    check_before = check_date(not_before);
    check_after = check_date(not_after);

    // check data ranges
    if (check_before == -1 && check_after == 1) {
        return 1;
    }

    return 0;
}


int validate_common_name(X509 *cert, const char *domain_url) {
    int lastpos = -1, match;
    X509_NAME *subject_name = NULL;
    X509_NAME_ENTRY *entry = NULL;
    ASN1_STRING *entry_data = NULL;
    unsigned char *common_name;

    // Get subject name
    subject_name = X509_get_subject_name(cert);
    if (!subject_name) {
        fprintf(stderr, "Subject name failed\n");
        exit(EXIT_FAILURE);
    }

    // Get common name
    lastpos = X509_NAME_get_index_by_NID(subject_name, NID_commonName, lastpos);
    if (lastpos == -1) {
        fprintf(stderr, "Common name not found\n");
        exit(EXIT_FAILURE);
    }

    // Get entry
    entry = X509_NAME_get_entry(subject_name, lastpos);
    if (!entry) {
        fprintf(stderr, "Index is invalid\n");
        exit(EXIT_FAILURE);
    }

    // Get entry data
    entry_data = X509_NAME_ENTRY_get_data(entry);

    // print entry in utf-8 string format
    ASN1_STRING_to_UTF8(&common_name, entry_data);

    match = fnmatch((const char *)common_name, domain_url, 0);
    if (match == 0) {
        return 1;
    }

    return 0;
}

int verify_certificate(const char *cert_path, const char *url) {
    BIO *cert_bio = NULL; //, *output = NULL;
    X509 *cert = NULL;
    int read_cert_bio;

    // Initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    // Create BIO object to read certificate
    cert_bio = BIO_new(BIO_s_file());

    // Read certificate into BIO
    read_cert_bio = BIO_read_filename(cert_bio, cert_path);
    if (!read_cert_bio) {
        fprintf(stderr, "Error in reading cert BIO filename\n");
        exit(EXIT_FAILURE);
    }

    // Load certificate into bio
    cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    if (!cert) {
        fprintf(stderr, "Error in loading certificate\n");
        exit(EXIT_FAILURE);
    }

    if (validate_dates(cert) && validate_common_name(cert, url)) {
        return 1;
    }

    //output = BIO_new_fp(stdout, BIO_NOCLOSE);
    //X509_print_ex(output, cert, XN_FLAG_COMPAT, X509_FLAG_COMPAT);

    return 0;
}

int main(int argc, char *argv[]) {
    certificates_t *certificates = NULL;
    int result;

    if (argc != 2) {
        fprintf(stderr, "Usage: ./certcheck [relative path to csv file]\n");
        exit(EXIT_FAILURE);
    }

    certificates = read_input_csv(argv[1]);

    for (size_t i = 0; i < certificates->n; i++) {
        result = verify_certificate(certificates->info[i].path, certificates->info[i].url);
        printf("%d\n", result);
    }

    exit(EXIT_SUCCESS);
}
