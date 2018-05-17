#ifndef FILE_H
#define FILE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "certlist.h"

#define BUFFER_SIZE 1024

list_t *read_input_csv(const char *csv_path);

void write_results(const char *filename, list_t *certificates);

#endif
