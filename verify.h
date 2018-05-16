#ifndef VERIFY_H
#define VERIFY_H

#define MIN_RSA_LENGTH 2048
#define MAX_VALID_EXTENSIONS 2
#define BUFFER_SIZE 1024

enum State {NOT_FOUND, FOUND};
enum Time {SOONER = -1, LATER = 1, SAME = 0};

int verify_certificate(const char *cert_path, const char *url);

#endif
