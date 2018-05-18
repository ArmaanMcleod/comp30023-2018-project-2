#include "filehandle.h"
#include "verify.h"

// Reads certificate files into linked list
list_t *read_input_csv(const char *csv_path) {
    FILE *stream = NULL;
    char buffer[BUFFER_SIZE] = {0};
    char *temp = NULL, *path = NULL, *hostname = NULL, *saveptr = NULL;
    list_t *certificates = NULL;
    size_t slen;
    const char *delim = " ,";
    certificate_t *info = NULL;

    // Initialise certificates
    certificates = initialise_certificates();

    // Open csv file
    stream = fopen(csv_path, "r");
    if (stream == NULL) {
        fprintf(stderr, "Failed to open file\n");
        exit(EXIT_FAILURE);
    }

    // Read through each line
    while (fgets(buffer, sizeof buffer, stream) != NULL) {
        slen = strlen(buffer);

        // Remove trailing newline character
        if (slen > 0 && buffer[slen-1] == '\n') {
            buffer[slen-1] = '\0';
        }

        // Create temporary node
        info = malloc(sizeof(*info));
        if (info == NULL) {
            free(info);
            fprintf(stderr, "Cannot malloc() node for certificate info\n");
            exit(EXIT_FAILURE);
        }

        // copy buffer
        temp = strdup(buffer);
        if (temp == NULL) {
            free(temp);
            fprintf(stderr, "Error: strdup() failed to copy buffer\n");
            exit(EXIT_FAILURE);
        }

        // Extract path
        path = strtok_r(temp, delim, &saveptr);
        info->path = strdup(path);
        if (info->path == NULL) {
            free(info->path);
            fprintf(stderr, "Error: stdup() can't parse path\n");
            exit(EXIT_FAILURE);
        }

        // Extract hostname
        hostname = strtok_r(NULL, delim, &saveptr);
        info->hostname = strdup(hostname);
        if (info->hostname == NULL) {
            free(info->hostname);
            fprintf(stderr, "Error: strdup() can't parse hostname\n");
            exit(EXIT_FAILURE);
        }

        // Add certificate to list
        add_certificate(certificates, info);

        free(temp);
    }

    fclose(stream);

    return certificates;
}

// Write results to csv output file
void write_results(const char *filename, list_t *certificates) {
    FILE *output = NULL;
    int result;
    node_t *curr = certificates->head;

    // Open the file in write mode
    output = fopen(filename, "w");
    if (output == NULL) {
        fprintf(stderr, "Cannot create output file\n");
        exit(EXIT_FAILURE);
    }

    // Write to csv file
    while (curr != NULL) {
        result = verify_certificate(curr->info->path, curr->info->hostname);
        fprintf(output, "%s,%s,%d\n", curr->info->path,
                                      curr->info->hostname, result);
        curr = curr->next;
    }

    fclose(output);

}
