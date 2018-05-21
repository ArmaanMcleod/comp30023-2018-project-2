#include "verify.h"

// Check if date is valid
static int check_date(const ASN1_TIME *time_to) {
    int day, sec;

    // Not before
    if (!ASN1_TIME_diff(&day, &sec, NULL, time_to)) {
        fprintf(stderr, "Invalid time format\n");
        exit(EXIT_FAILURE);
    }

    // Later
    if (day > 0 || sec > 0) {
        return TIME_LATER;

    // Sooner
    } else if (day < 0 || sec < 0) {
        return TIME_SOONER;
    }

    // Same
    return TIME_SAME;
}

// Validates not before and after dates in certificate
static int validate_dates(const X509 *cert) {
    ASN1_TIME *not_before = NULL, *not_after = NULL;
    int check_before, check_after;

    // Get time periods
    not_before = X509_get_notBefore(cert);
    not_after = X509_get_notAfter(cert);

    check_before = check_date(not_before);
    check_after = check_date(not_after);

    // check valid data ranges
    return (check_before == TIME_SOONER && check_after == TIME_LATER) ||
           (check_before == TIME_SAME && check_after == TIME_LATER) ||
           (check_before == TIME_SOONER && check_after == TIME_SAME) ||
           (check_before == TIME_SAME && check_after == TIME_SAME);
}

// Validates domain name in common name in certificate
static int validate_common_name(X509 *cert, const char *hostname) {
    int lastpos = -1, match;
    X509_NAME *subject_name = NULL;
    X509_NAME_ENTRY *entry = NULL;
    ASN1_STRING *entry_data = NULL;
    char *common_name = NULL;

    // Get subject name
    subject_name = X509_get_subject_name(cert);
    if (subject_name == NULL) {
        fprintf(stderr, "Subject name failed\n");
        exit(EXIT_FAILURE);
    }

    // Get common name
    lastpos = X509_NAME_get_index_by_NID(subject_name, NID_commonName,
                                         lastpos);
    if (lastpos == CN_NOT_PRESENT) {
        return CN_NOT_FOUND;
    }

    // Get entry
    entry = X509_NAME_get_entry(subject_name, lastpos);
    if (entry == NULL) {
        fprintf(stderr, "Index is invalid\n");
        exit(EXIT_FAILURE);
    }

    // Get entry data
    entry_data = X509_NAME_ENTRY_get_data(entry);
    if (entry_data == NULL) {
        fprintf(stderr, "Entry is invalid\n");
        exit(EXIT_FAILURE);
    }

    // Print entry in string format
    common_name = (char *)ASN1_STRING_data(entry_data);

    // Validate host name
    match = fnmatch(common_name, hostname, FNM_CASEFOLD);

    return (match == 0) ? CN_FOUND : CN_NOT_FOUND;
}

// Validates minimum RSA key length in certificate
static int validate_RSA_key_length(X509 *cert) {
    EVP_PKEY *public_key = NULL;
    int length;

    // Get the public_key
    public_key = X509_get_pubkey(cert);
    if (public_key == NULL) {
        return KEY_NOT_PRESENT;
    }

    // Verify that public key is RSA
    if (public_key->type == EVP_PKEY_RSA) {

        // Get length of key
        length = EVP_PKEY_bits(public_key);

        // If its less than minimum
        if (length < MIN_RSA_LENGTH) {
            EVP_PKEY_free(public_key);
            return KEY_SHORTER;
        }
    }

    EVP_PKEY_free(public_key);

    // Otherwise, key length is valid
    return KEY_CORRECT;
}

static int validate_extension(X509 *cert, int extension, const char *value) {
    X509_EXTENSION *ex = NULL;
    BUF_MEM *bptr = NULL;
    char *buffer = NULL, *match = NULL;
    BIO *ext_bio = NULL;

    // Get the extension
    ex = X509_get_ext(cert, extension);

    // Create the bio
    ext_bio = BIO_new(BIO_s_mem());

    // Check extension can be read into bio
    if (!X509V3_EXT_print(ext_bio, ex, 0, 0)) {
        BIO_printf(ext_bio, "Error in reading extensison in BIO\n");
        exit(EXIT_FAILURE);
    }

    BIO_flush(ext_bio);
    BIO_get_mem_ptr(ext_bio, &bptr);
    BIO_set_close(ext_bio, BIO_NOCLOSE);

    // Allocate buffer for extension value
    buffer = malloc(bptr->length + 1);
    if (buffer == NULL) {
        free(buffer);
        fprintf(stderr, "Cannot malloc() %zu bytes for buffer\n",
                         bptr->length);
        exit(EXIT_FAILURE);
    }

    // Copy extension into buffer
    memcpy(buffer, bptr->data, bptr->length);
    buffer[bptr->length] = '\0';

    BIO_free_all(ext_bio);
    BUF_MEM_free(bptr);

    // Match extension values
    match = strstr(buffer, value);
    if (match == NULL) {
        free(buffer);
        return EXTENSION_NOT_FOUND;
    }

    free(buffer);
    return EXTENSION_FOUND;
}

// Validates key usages and constraints
static int validate_key_usage_constraints(X509 *cert) {
    int extended_key = -1, constraint = -1;
    int validate_extended_key, validate_constraint;
    const char *constraint_value = "CA:FALSE";
    const char *extended_key_value = "TLS Web Server Authentication";

    // Get extended key
    extended_key = X509_get_ext_by_NID(cert, NID_ext_key_usage, extended_key);
    if (extended_key == EXTENSION_ERROR) {
        return EXTENSION_NOT_FOUND;
    }

    // Get constraint
    constraint = X509_get_ext_by_NID(cert, NID_basic_constraints, constraint);
    if (constraint == EXTENSION_ERROR) {
        return EXTENSION_NOT_FOUND;
    }

    // Validate extended key
    validate_extended_key = validate_extension(cert, extended_key,
                                               extended_key_value);

    // Validate constraint
    validate_constraint = validate_extension(cert, constraint,
                                             constraint_value);

    return validate_extended_key == EXTENSION_FOUND &&
           validate_constraint == EXTENSION_FOUND;
}

// Validate alternate name extensions
static int validate_subject_alternative_name(X509 *cert, const char *hostname) {
    STACK_OF(GENERAL_NAME) *san_names = NULL;
    size_t num_sans;
    GENERAL_NAME *current_name = NULL;
    char *dns_name = NULL;
    int match;

    // Extract names within SAN extension
    san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (san_names == NULL) {
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
        return SAN_NOT_PRESENT;
    }

    // Get number of extensions
    num_sans = sk_GENERAL_NAME_num(san_names);

    for (size_t i = 0; i < num_sans; i++) {

        // Get name of extension
        current_name = sk_GENERAL_NAME_value(san_names, i);

        // Extract only DNS types
        if (current_name->type == GEN_DNS) {
            dns_name = (char *)ASN1_STRING_data(current_name->d.dNSName);

            // Match extension
            match = fnmatch(dns_name, hostname, FNM_CASEFOLD);
            if (!match) {
                sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
                return SAN_FOUND;
            }

        }
    }

    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

    return SAN_NOT_FOUND;
}

// Veritify TLS certificate
int verify_certificate(const char *cert_path, const char *hostname) {
    BIO *cert_bio = NULL, *out_bio = NULL;
    X509 *cert = NULL;
    int read_cert_bio, extension, result;

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
        BIO_free_all(cert_bio);
        BIO_printf(out_bio, "Error in reading cert BIO filename\n");
        exit(EXIT_FAILURE);
    }

    // Load certificate into bio
    cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    if (cert == NULL) {
        X509_free(cert);
        BIO_printf(out_bio, "Error in loading certificate\n");
        exit(EXIT_FAILURE);
    }

    // First try and get the common name
    extension = validate_common_name(cert, hostname);

    // If no valid common name exist, check subject alternate names
    if (extension == CN_NOT_FOUND || CN_NOT_FOUND) {
        extension = validate_subject_alternative_name(cert, hostname);

        // If subject alternate name not found or not present, SAN invalid
        if (extension == SAN_NOT_FOUND || extension == SAN_NOT_PRESENT) {
            extension = EXTENSION_NOT_FOUND;
        } else {
            extension = EXTENSION_FOUND;
        }
    }

    // Validate certificate conditions
    // Do explicit checks just in case
    result = validate_dates(cert) &&
             validate_RSA_key_length(cert) == KEY_CORRECT &&
             validate_key_usage_constraints(cert) == EXTENSION_FOUND &&
             extension == EXTENSION_FOUND;

     // Free up certificate contents
     X509_free(cert);
     BIO_free_all(cert_bio);
     BIO_free_all(out_bio);

    return result;
}
