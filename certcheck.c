/*============================================================================
#                             COMP30023 Assignment 2                         #
#                           TLS X509 certificate checker                     #
#      FileName: certcheck.c                                                 #
#       Purpose: Main function which checks all certificates from file       #
#        Author: Armaan McLeod                                               #
#         Email: dhaliwala@student.unimelb.edu.au                            #
# StudentNumber: 837674                                                      #
#      UserName: dhaliwala                                                   #
============================================================================*/

#include "certlist.h"
#include "filehandle.h"

int main(int argc, char *argv[]) {
    list_t *certificates = NULL;
    const char *output = "output.csv";

    // Make sure only two arguements given
    if (argc != 2) {
        fprintf(stderr, "Usage: ./certcheck [relative path to csv file]\n");
        exit(EXIT_FAILURE);
    }

    // Get certificates list
    certificates = read_input_csv(argv[1]);

    // Write results
    write_results(output, certificates);

    // Free all pointers
    free_certificates(certificates);

    exit(EXIT_SUCCESS);
}
