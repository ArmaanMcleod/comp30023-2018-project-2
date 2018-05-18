#include "verify.h"
#include "wildcard.h"

const char *CONSTRAINT_NAME = "Basic Constraints";
const char *CONSTRAINT_VALUE = "CA:FALSE";
const char *EXTENDED_KEY_NAME = "Extended Key Usage";
const char *EXTENDED_KEY_VALUE = "TLS Web Server Authentication";

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
    unsigned char *common_name = NULL;

    // Get subject name
    subject_name = X509_get_subject_name(cert);
    if (subject_name == NULL) {
        fprintf(stderr, "Subject name failed\n");
        exit(EXIT_FAILURE);
    }

    // Get common name
    lastpos = X509_NAME_get_index_by_NID(subject_name, NID_commonName,
                                         lastpos);
    if (lastpos == -1) {
        fprintf(stderr, "Common name not found\n");
        exit(EXIT_FAILURE);
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
    common_name = ASN1_STRING_data(entry_data);

    // Validate host name
    match = fnmatch((const char*)common_name, hostname, FNM_CASEFOLD);

    return (match == 0) ? HOST_FOUND : HOST_NOT_FOUND;
}

// Validates minimum RSA key length in certificate
static int validate_RSA_key_length(X509 *cert) {
    EVP_PKEY *public_key = NULL;
    int length;

    // Get the public_key
    public_key = X509_get_pubkey(cert);
    if (public_key == NULL) {
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
            return KEY_SHORTER;
        }
    }

    EVP_PKEY_free(public_key);

    // Otherwise, key length is valid
    return KEY_CORRECT;
}

// Checks extensions exist in list
static int validate_extension(STACK_OF(X509_EXTENSION) *ext_list,
                              const char *extension_name,
                              const char *extension_value) {
    X509_EXTENSION *ext = NULL;
    ASN1_OBJECT *obj = NULL;
    BIO *ext_bio = NULL;
    BUF_MEM *bptr = NULL;
    char *buffer = NULL;
    char ext_buffer[EXT_BUFFER_SIZE] = {0};
    size_t num_exts;

    // Get number of extension
    num_exts = (ext_list != NULL) ? sk_X509_EXTENSION_num(ext_list) : 0;

    // Go over the extensions
    for (size_t i = 0; i < num_exts; i++) {
        // Get extension
        ext = sk_X509_EXTENSION_value(ext_list, i);

        // Get object
        obj = X509_EXTENSION_get_object(ext);
        memset(ext_buffer, '\0', sizeof ext_buffer);
        OBJ_obj2txt(ext_buffer, EXT_BUFFER_SIZE, obj, 0);

        // Check if extension name matches
        if (strstr(ext_buffer, extension_name)) {
            // Get extension bio
            ext_bio = BIO_new(BIO_s_mem());
            if (!X509V3_EXT_print(ext_bio, ext, 0, 0)) {
                fprintf(stderr, "Error reading in extension\n");
                exit(EXIT_FAILURE);
            }

            // Insert pointer into bio and close it
            BIO_flush(ext_bio);
            BIO_get_mem_ptr(ext_bio, &bptr);
            BIO_set_close(ext_bio, BIO_NOCLOSE);
            BIO_free_all(ext_bio);

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

            BUF_MEM_free(bptr);

            // Check if extension value is correct
            if (strstr(buffer, extension_value)) {
                free(buffer);
                return EXTENSION_FOUND;
            }

            free(buffer);
        }
    }

    return EXTENSION_NOT_FOUND;
}

// Validates key usages and constraints
static int validate_key_usage_constraints(const X509 *cert) {
    X509_CINF *cert_info = NULL;
    STACK_OF(X509_EXTENSION) *ext_list = NULL;

    // Extract certificate extension
    cert_info = cert->cert_info;
    ext_list = cert_info->extensions;

    return validate_extension(ext_list, CONSTRAINT_NAME, CONSTRAINT_VALUE) &&
           validate_extension(ext_list, EXTENDED_KEY_NAME, EXTENDED_KEY_VALUE);
}

// Validate alternate name extensions
static int validate_subject_alternative_name(X509 *cert, const char *hostname) {
    STACK_OF(GENERAL_NAME) *san_names = NULL;
    size_t num_sans;
    GENERAL_NAME *current_name = NULL;
    unsigned char *dns_name = NULL;
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
            dns_name = ASN1_STRING_data(current_name->d.dNSName);

            // Match extension
            match = fnmatch((const char*)dns_name, hostname, FNM_CASEFOLD);
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
    if (!extension) {
        extension = validate_subject_alternative_name(cert, hostname);

        // If subject alternate name not found or not present, SAN invalid
        if (extension == SAN_NOT_FOUND || extension == SAN_NOT_PRESENT) {
            extension = EXTENSION_NOT_FOUND;
        } else {
            extension = EXTENSION_FOUND;
        }
    }

    // Validate certificate conditions
    result = validate_dates(cert) &&
             validate_RSA_key_length(cert) &&
             validate_key_usage_constraints(cert) &&
             extension;

     // Free up certificate contents
     X509_free(cert);
     BIO_free_all(cert_bio);
     BIO_free_all(out_bio);

    return result;
}
