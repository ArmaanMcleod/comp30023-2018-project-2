#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
        fprintf(stderr, "Failed to open file");
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

int main(int argc, char *argv[]) {
    certificates_t *certificates = NULL;

    if (argc != 2) {
        fprintf(stderr, "Usage: ./certcheck [csv file]\n");
        exit(EXIT_FAILURE);
    }

    certificates = read_input_csv(argv[1]);

    for (size_t i = 0; i < certificates->n; i++) {
        printf("%s,%s\n",
        certificates->info[i].path,
        certificates->info[i].url);
    }

    exit(EXIT_SUCCESS);
}
