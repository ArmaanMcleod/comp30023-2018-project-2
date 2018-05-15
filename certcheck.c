#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define START_SIZE 5;
#define BUFFER_SIZE 1024
#define MIN_RSA_LENGTH 2048
#define MAX_VALID_EXTENSIONS 2

typedef struct {
    char *path;
    char *domain_url;
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
    char *temp = NULL, *path = NULL, *domain_url = NULL, *saveptr = NULL;
    certificates_t *certificates = NULL;
    size_t slen, num_certificates = START_SIZE;
    const char *delim = " ,";
    void *new_ptr = NULL;

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
            new_ptr = realloc(certificates->info,
                            num_certificates * sizeof(*(certificates->info)));
            if (!certificates) {
                fprintf(stderr, "Error: realloc() failed to resize buffer to"
                                 "%zu bytes\n", num_certificates);
                exit(EXIT_FAILURE);
            }

            certificates->info =  new_ptr;
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

        // Extract domain_url
        domain_url = strtok_r(NULL, delim, &saveptr);
        certificates->info[certificates->n].domain_url = strdup(domain_url);
        if (!certificates->info[certificates->n].domain_url) {
            fprintf(stderr, "Error: strdup() can't parse domain_url\n");
            exit(EXIT_FAILURE);
        }

        certificates->n++;

        free(temp);
    }

    fclose(stream);

    return certificates;
}

// Check if date is valid
int check_date(const ASN1_TIME *time_to) {
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

// Validates not before and after dates in certificate
int validate_dates(const X509 *cert) {
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

// Validates domain name in common name in certificate
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

    // Match the string
    match = fnmatch((const char *)common_name, domain_url, FNM_NOESCAPE);
    OPENSSL_free(common_name);

    if (match == 0) {
        return 1;
    }

    return 0;
}

// Validates minimum RSA key length in certificate
int validate_RSA_key_length(X509 *cert) {
    EVP_PKEY *public_key = NULL;
    int length;

    // Get the public_key
    public_key = X509_get_pubkey(cert);
    if (!public_key) {
        fprintf(stderr, "Error getting public key from certificate\n");
        exit(EXIT_FAILURE);
    }

    // Verify that public key is RSA
    if (public_key->type == EVP_PKEY_RSA) {

        // Get length of key
        length = EVP_PKEY_bits(public_key);

        // If its less than minimum
        if (length < MIN_RSA_LENGTH) {
            EVP_PKEY_free(public_key);
            return 0;
        }
    }

    EVP_PKEY_free(public_key);

    // Otherwise, key length is valid
    return 1;
}

int validate_key_usage_constraints(const X509 *cert) {
    X509_CINF *cert_info = NULL;
    STACK_OF(X509_EXTENSION) * ext_list = NULL;
    size_t num_exts;
    ASN1_OBJECT *obj = NULL;
    X509_EXTENSION *ext = NULL;
    BIO *ext_bio = NULL;
    BUF_MEM *bptr = NULL;
    char ext_buffer[BUFFER_SIZE] = {0};
    char *buffer = NULL;
    int num_valid = 0;
    char *check_constraint = NULL, *constraint_value = NULL;
    char *check_extended_key_usage = NULL, *key_value = NULL;

    // Extract certificate extension
    cert_info = cert->cert_info;
    ext_list = cert_info->extensions;

    // Get number of extension
    if (ext_list) {
        num_exts = sk_X509_EXTENSION_num(ext_list);
    } else {
        num_exts = 0;
    }

    // Loop over the extension;
    for (size_t i = 0; i < num_exts; i++) {
        // Get extension
        ext = sk_X509_EXTENSION_value(ext_list, i);

        // Get object
        obj = X509_EXTENSION_get_object(ext);
        memset(ext_buffer, '\0', sizeof ext_buffer);
        OBJ_obj2txt(ext_buffer, BUFFER_SIZE, obj, 0);

        // Get extension bio
        ext_bio = BIO_new(BIO_s_mem());

        // Validate extensions
        if (!X509V3_EXT_print(ext_bio, ext, 0, 0)) {
            fprintf(stderr, "Error reading in extension\n");
            continue;
        }

        // Insert pointer into bio and close it
        BIO_flush(ext_bio);
        BIO_get_mem_ptr(ext_bio, &bptr);
        BIO_set_close(ext_bio, BIO_NOCLOSE);

        // Allocate buffer for extension value
        buffer = malloc(bptr->length + 1);
        if (!buffer) {
            fprintf(stderr, "Cannot malloc() %zu bytes for buffer\n",
                             bptr->length);
            exit(EXIT_FAILURE);
        }

        // Copy extension into buffer
        memcpy(buffer, bptr->data, bptr->length);
        buffer[bptr->length] = '\0';

        // Checks constraints
        check_constraint = strstr(ext_buffer, "Basic Constraints");
        if (check_constraint != NULL) {
            constraint_value = strstr(buffer, "CA:FALSE");
            if (constraint_value != NULL) {
                num_valid++;
            }
        }

        // Checks key usages
        check_extended_key_usage = strstr(ext_buffer, "Extended Key Usage");
        if (check_extended_key_usage != NULL) {
            key_value = strstr(buffer, "TLS Web Server Authentication");
            if (key_value != NULL) {
                num_valid++;
            }
        }

        free(buffer);
        BUF_MEM_free(bptr);
        BIO_free_all(ext_bio);
    }

    // Check number of valid checks
    if (num_valid == MAX_VALID_EXTENSIONS) {
        return 1;
    }

    return 0;
}



int validate_subject_alternative_extension(X509 *cert, const char *domain_url) {
    STACK_OF(GENERAL_NAME) *san_names = NULL;
    size_t num_sans;
    GENERAL_NAME *current_name = NULL;
    unsigned char *dns_name = NULL;
    int match;

    // Extract names within SAN extension
    san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);

    if (!san_names) {
        return -1;
    }

    num_sans = sk_GENERAL_NAME_num(san_names);

    for (size_t i = 0; i < num_sans; i++) {
        current_name = sk_GENERAL_NAME_value(san_names, i);

        if (current_name->type == GEN_DNS) {
            dns_name = ASN1_STRING_data(current_name->d.dNSName);

            match = fnmatch((const char *)dns_name, domain_url, FNM_NOESCAPE);
            if (match == 0) {
                return 1;
            }
        }
    }

    return 0;
}

// Free certificate and bios
void free_certificate_contents(X509 *cert, BIO *cert_bio, BIO *out_bio) {
    X509_free(cert);
    BIO_free_all(cert_bio);
    BIO_free_all(out_bio);
}

int verify_certificate(const char *cert_path, const char *domain_url) {
    BIO *cert_bio = NULL, *out_bio = NULL;
    X509 *cert = NULL;
    int read_cert_bio, extension;

    // Initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    // Create BIO object to read certificate
    cert_bio = BIO_new(BIO_s_file());
    out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

    // Read certificate into BIO
    read_cert_bio = BIO_read_filename(cert_bio, cert_path);
    if (!read_cert_bio) {
        fprintf(stderr, "Error in reading cert BIO filename\n");
        exit(EXIT_FAILURE);
    }

    // Load certificate into bio
    cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    if (!cert) {
        BIO_printf(out_bio, "Error in loading certificate\n");
        exit(EXIT_FAILURE);
    }

    //X509_print_ex(out_bio, cert, XN_FLAG_COMPAT, X509_FLAG_COMPAT);

    extension = validate_subject_alternative_extension(cert, domain_url);
    if (extension == -1) {
        extension = validate_common_name(cert, domain_url);
    }

    // Validate certificate conditions
    if (validate_dates(cert) &&
        extension &&
        validate_RSA_key_length(cert) &&
        validate_key_usage_constraints(cert)) {

        free_certificate_contents(cert, cert_bio, out_bio);

        return 1;
    }

    free_certificate_contents(cert, cert_bio, out_bio);

    return 0;
}

// Free all certificate information stored
void free_certificates(certificates_t *certificates) {
    for (size_t i = 0; i < certificates->n; i++) {
        free(certificates->info[i].path);
        free(certificates->info[i].domain_url);
    }
    free(certificates->info);
    free(certificates);
}

void write_results(const char *filename, const certificates_t *certificates) {
    FILE *output = NULL;
    int result;

    output = fopen(filename, "w");
    if (!output) {
        fprintf(stderr, "Cannot create output file\n");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < certificates->n; i++) {
        //printf("%zu\n", i+1);
        result = verify_certificate(certificates->info[i].path,
                                    certificates->info[i].domain_url);

        fprintf(output, "%s,%s,%d\n", certificates->info[i].path,
                                      certificates->info[i].domain_url,
                                      result);
    }

    fclose(output);

}

int main(int argc, char *argv[]) {
    certificates_t *certificates = NULL;
    const char *output = "output.csv";

    if (argc != 2) {
        fprintf(stderr, "Usage: ./certcheck [relative path to csv file]\n");
        exit(EXIT_FAILURE);
    }

    certificates = read_input_csv(argv[1]);

    write_results(output, certificates);

    free_certificates(certificates);

    exit(EXIT_SUCCESS);
}
