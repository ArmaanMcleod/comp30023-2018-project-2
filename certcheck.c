#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *path;
    const char *url;
} certificate_t;

#define START_SIZE 10;
#define BUFFER_SIZE 1024

certificate_t *read_input_csv(const char *csv_path) {
    FILE *stream = NULL;
    char buffer[BUFFER_SIZE] = {0};
    char *temp = NULL, *path = NULL, *url, *saveptr = NULL;
    certificate_t *certificates = NULL;
    size_t num_certificates = START_SIZE;
    size_t line = 0;
    size_t slen;
    const char *delim = " ,";

    // Allocate certificates array
    certificates = malloc(num_certificates * sizeof(*certificates));
    if (!certificates) {
        fprintf(stderr, "Error: cannot malloc() %zu certificates\n", num_certificates);
        exit(EXIT_FAILURE);
    }

    // Open csv file
    stream = fopen(csv_path, "r");
    if (!stream) {
        fprintf(stderr, "Failed to open file");
        exit(EXIT_FAILURE);
    }

    // Read through each line
    while (fgets(buffer, sizeof buffer, stream) != NULL) {
        slen = strlen(buffer);

        // Remove trailing newline character
        if (slen > 0 && buffer[slen-1] == '\n') {
            buffer[slen-1] = '\0';
        }

        temp = strdup(buffer);
        if (!temp) {
            fprintf(stderr, "Error: strdup() failed to copy buffer\n");
            exit(EXIT_FAILURE);
        }

        path = strtok_r(temp, delim, &saveptr);
        certificates[line].path = strdup(path);
        if (!certificates[line].path) {
            fprintf(stderr, "Error: stdup() can't parse path\n");
            exit(EXIT_FAILURE);
        }

        url = strtok_r(NULL, delim, &saveptr);
        certificates[line].url = strdup(url);
        if (!certificates[line].url) {
            fprintf(stderr, "Error: stdup() can't parse url\n");
            exit(EXIT_FAILURE);
        }

        line++;
    }

    return certificates;
}

int main(int argc, char *argv[]) {
    certificate_t *certificates = NULL;

    if (argc != 2) {
        fprintf(stderr, "Usage: ./certcheck [csv file]\n");
        exit(EXIT_FAILURE);
    }

    certificates = read_input_csv(argv[1]);

    exit(EXIT_SUCCESS);
}
