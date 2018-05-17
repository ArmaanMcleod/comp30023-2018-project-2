#ifndef FILE_H
#define FILE_H

#include "certlist.h"

list_t *read_input_csv(const char *csv_path);

void write_results(const char *filename, list_t *certificates);

#endif
