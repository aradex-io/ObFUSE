#ifndef OBFUSE_UTILS_H
#define OBFUSE_UTILS_H

#include <stdio.h>
#include <errno.h>

#define OBFUSE_LOG(fmt, ...) \
    fprintf(stderr, "obfuse: " fmt "\n", ##__VA_ARGS__)

#define OBFUSE_ERR(fmt, ...) \
    fprintf(stderr, "obfuse: error: " fmt "\n", ##__VA_ARGS__)

/* Header stored at the beginning of each encrypted file on disk */
#define OBFUSE_FILE_MAGIC  "OBFS"
#define OBFUSE_FILE_MAGIC_LEN 4
#define OBFUSE_FILE_VERSION 1

#endif /* OBFUSE_UTILS_H */
