#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <termios.h>

#include "crypto.h"
#include "utils.h"

/* Per-file header stored on disk:
 *   [4 bytes magic "OBFS"] [1 byte version] [16 bytes IV]
 * Total: 21 bytes prepended to the ciphertext. */
#define OBFUSE_HDR_LEN (OBFUSE_FILE_MAGIC_LEN + 1 + OBFUSE_IV_LEN)

struct obfuse_state {
    char *source_dir;
    uint8_t key[OBFUSE_KEY_LEN];
};

static struct obfuse_state *obfuse_get_state(void)
{
    return (struct obfuse_state *)fuse_get_context()->private_data;
}

/* Build the real path in the source directory */
static void obfuse_fullpath(char *buf, size_t buflen, const char *path)
{
    struct obfuse_state *st = obfuse_get_state();
    snprintf(buf, buflen, "%s%s", st->source_dir, path);
}

/* --- FUSE Operations --- */

static int obfuse_getattr(const char *path, struct stat *stbuf,
                           struct fuse_file_info *fi)
{
    (void)fi;
    char fpath[PATH_MAX];
    obfuse_fullpath(fpath, sizeof(fpath), path);

    int res = lstat(fpath, stbuf);
    if (res == -1)
        return -errno;

    /* Adjust reported size for regular files: subtract header */
    if (S_ISREG(stbuf->st_mode) && stbuf->st_size > OBFUSE_HDR_LEN)
        stbuf->st_size -= OBFUSE_HDR_LEN;
    else if (S_ISREG(stbuf->st_mode))
        stbuf->st_size = 0;

    return 0;
}

static int obfuse_readdir(const char *path, void *buf,
                           fuse_fill_dir_t filler, off_t offset,
                           struct fuse_file_info *fi,
                           enum fuse_readdir_flags flags)
{
    (void)offset;
    (void)fi;
    (void)flags;
    char fpath[PATH_MAX];
    obfuse_fullpath(fpath, sizeof(fpath), path);

    DIR *dp = opendir(fpath);
    if (!dp)
        return -errno;

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (filler(buf, de->d_name, NULL, 0, 0))
            break;
    }

    closedir(dp);
    return 0;
}

static int obfuse_open(const char *path, struct fuse_file_info *fi)
{
    char fpath[PATH_MAX];
    obfuse_fullpath(fpath, sizeof(fpath), path);

    int fd = open(fpath, fi->flags);
    if (fd == -1)
        return -errno;

    fi->fh = (uint64_t)fd;
    return 0;
}

static int obfuse_read(const char *path, char *buf, size_t size,
                        off_t offset, struct fuse_file_info *fi)
{
    (void)path;
    struct obfuse_state *st = obfuse_get_state();
    int fd = (int)fi->fh;

    /* Read the file header to get the IV */
    uint8_t hdr[OBFUSE_HDR_LEN];
    ssize_t hdr_read = pread(fd, hdr, OBFUSE_HDR_LEN, 0);
    if (hdr_read < (ssize_t)OBFUSE_HDR_LEN)
        return -EIO;

    if (memcmp(hdr, OBFUSE_FILE_MAGIC, OBFUSE_FILE_MAGIC_LEN) != 0)
        return -EIO;

    uint8_t *iv = hdr + OBFUSE_FILE_MAGIC_LEN + 1;

    /* Read ciphertext from the offset (adjusted for header) */
    ssize_t n = pread(fd, buf, size, offset + OBFUSE_HDR_LEN);
    if (n < 0)
        return -errno;

    /* Decrypt in place */
    if (obfuse_decrypt(st->key, iv, (uint8_t *)buf, (size_t)n, offset) != 0)
        return -EIO;

    return (int)n;
}

static int obfuse_write(const char *path, const char *buf, size_t size,
                         off_t offset, struct fuse_file_info *fi)
{
    (void)path;
    struct obfuse_state *st = obfuse_get_state();
    int fd = (int)fi->fh;

    /* Read or create the file header */
    uint8_t hdr[OBFUSE_HDR_LEN];
    uint8_t iv[OBFUSE_IV_LEN];
    ssize_t hdr_read = pread(fd, hdr, OBFUSE_HDR_LEN, 0);

    if (hdr_read >= (ssize_t)OBFUSE_HDR_LEN &&
        memcmp(hdr, OBFUSE_FILE_MAGIC, OBFUSE_FILE_MAGIC_LEN) == 0) {
        /* Existing file — extract IV */
        memcpy(iv, hdr + OBFUSE_FILE_MAGIC_LEN + 1, OBFUSE_IV_LEN);
    } else {
        /* New file — generate IV and write header */
        if (obfuse_random_bytes(iv, OBFUSE_IV_LEN) != 0)
            return -EIO;

        memcpy(hdr, OBFUSE_FILE_MAGIC, OBFUSE_FILE_MAGIC_LEN);
        hdr[OBFUSE_FILE_MAGIC_LEN] = OBFUSE_FILE_VERSION;
        memcpy(hdr + OBFUSE_FILE_MAGIC_LEN + 1, iv, OBFUSE_IV_LEN);

        if (pwrite(fd, hdr, OBFUSE_HDR_LEN, 0) != OBFUSE_HDR_LEN)
            return -EIO;
    }

    /* Encrypt a copy of the buffer */
    uint8_t *enc_buf = malloc(size);
    if (!enc_buf)
        return -ENOMEM;

    memcpy(enc_buf, buf, size);
    if (obfuse_encrypt(st->key, iv, enc_buf, size, offset) != 0) {
        free(enc_buf);
        return -EIO;
    }

    ssize_t n = pwrite(fd, enc_buf, size, offset + OBFUSE_HDR_LEN);
    free(enc_buf);

    if (n < 0)
        return -errno;

    return (int)n;
}

static int obfuse_create(const char *path, mode_t mode,
                          struct fuse_file_info *fi)
{
    char fpath[PATH_MAX];
    obfuse_fullpath(fpath, sizeof(fpath), path);

    int fd = open(fpath, fi->flags, mode);
    if (fd == -1)
        return -errno;

    fi->fh = (uint64_t)fd;
    return 0;
}

static int obfuse_release(const char *path, struct fuse_file_info *fi)
{
    (void)path;
    close((int)fi->fh);
    return 0;
}

static int obfuse_truncate(const char *path, off_t size,
                            struct fuse_file_info *fi)
{
    (void)fi;
    char fpath[PATH_MAX];
    obfuse_fullpath(fpath, sizeof(fpath), path);

    /* Adjust for header */
    off_t real_size = (size > 0) ? size + OBFUSE_HDR_LEN : 0;

    int res = truncate(fpath, real_size);
    if (res == -1)
        return -errno;

    return 0;
}

static int obfuse_unlink(const char *path)
{
    char fpath[PATH_MAX];
    obfuse_fullpath(fpath, sizeof(fpath), path);

    int res = unlink(fpath);
    if (res == -1)
        return -errno;
    return 0;
}

static int obfuse_mkdir(const char *path, mode_t mode)
{
    char fpath[PATH_MAX];
    obfuse_fullpath(fpath, sizeof(fpath), path);

    int res = mkdir(fpath, mode);
    if (res == -1)
        return -errno;
    return 0;
}

static int obfuse_rmdir(const char *path)
{
    char fpath[PATH_MAX];
    obfuse_fullpath(fpath, sizeof(fpath), path);

    int res = rmdir(fpath);
    if (res == -1)
        return -errno;
    return 0;
}

static int obfuse_rename(const char *from, const char *to, unsigned int flags)
{
    (void)flags;
    char ffrom[PATH_MAX], fto[PATH_MAX];
    obfuse_fullpath(ffrom, sizeof(ffrom), from);
    obfuse_fullpath(fto, sizeof(fto), to);

    int res = rename(ffrom, fto);
    if (res == -1)
        return -errno;
    return 0;
}

static int obfuse_chmod(const char *path, mode_t mode,
                         struct fuse_file_info *fi)
{
    (void)fi;
    char fpath[PATH_MAX];
    obfuse_fullpath(fpath, sizeof(fpath), path);

    int res = chmod(fpath, mode);
    if (res == -1)
        return -errno;
    return 0;
}

static int obfuse_utimens(const char *path, const struct timespec ts[2],
                           struct fuse_file_info *fi)
{
    (void)fi;
    char fpath[PATH_MAX];
    obfuse_fullpath(fpath, sizeof(fpath), path);

    int res = utimensat(AT_FDCWD, fpath, ts, AT_SYMLINK_NOFOLLOW);
    if (res == -1)
        return -errno;
    return 0;
}

static const struct fuse_operations obfuse_ops = {
    .getattr  = obfuse_getattr,
    .readdir  = obfuse_readdir,
    .open     = obfuse_open,
    .read     = obfuse_read,
    .write    = obfuse_write,
    .create   = obfuse_create,
    .release  = obfuse_release,
    .truncate = obfuse_truncate,
    .unlink   = obfuse_unlink,
    .mkdir    = obfuse_mkdir,
    .rmdir    = obfuse_rmdir,
    .rename   = obfuse_rename,
    .chmod    = obfuse_chmod,
    .utimens  = obfuse_utimens,
};

static int read_passphrase(char *buf, size_t buflen)
{
    struct termios old, new;
    fprintf(stderr, "Passphrase: ");

    if (tcgetattr(STDIN_FILENO, &old) != 0)
        return -1;

    new = old;
    new.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &new);

    if (fgets(buf, (int)buflen, stdin) == NULL) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
        return -1;
    }

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    fprintf(stderr, "\n");

    /* Strip trailing newline */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';

    return 0;
}

static void usage(const char *progname)
{
    fprintf(stderr,
            "Usage: %s -s <source_dir> <mountpoint> [FUSE options]\n"
            "\n"
            "Options:\n"
            "  -s <dir>    Source directory for encrypted storage\n"
            "  -h          Show this help\n",
            progname);
}

int main(int argc, char *argv[])
{
    struct obfuse_state *state;
    char *source_dir = NULL;
    int fuse_argc = 0;
    char **fuse_argv = NULL;

    /* Parse our arguments before passing the rest to FUSE */
    fuse_argv = calloc((size_t)argc, sizeof(char *));
    if (!fuse_argv) {
        OBFUSE_ERR("out of memory");
        return 1;
    }

    fuse_argv[fuse_argc++] = argv[0];

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            source_dir = realpath(argv[++i], NULL);
            if (!source_dir) {
                OBFUSE_ERR("invalid source directory: %s", argv[i]);
                free(fuse_argv);
                return 1;
            }
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            free(fuse_argv);
            return 0;
        } else {
            fuse_argv[fuse_argc++] = argv[i];
        }
    }

    if (!source_dir) {
        usage(argv[0]);
        free(fuse_argv);
        return 1;
    }

    state = calloc(1, sizeof(*state));
    if (!state) {
        OBFUSE_ERR("out of memory");
        free(source_dir);
        free(fuse_argv);
        return 1;
    }
    state->source_dir = source_dir;

    /* Read passphrase and derive key */
    char passphrase[256];
    if (read_passphrase(passphrase, sizeof(passphrase)) != 0) {
        OBFUSE_ERR("failed to read passphrase");
        free(state->source_dir);
        free(state);
        free(fuse_argv);
        return 1;
    }

    /* Use a fixed salt derived from the source path for deterministic key.
     * In production, store the salt in a config file. */
    uint8_t salt[OBFUSE_SALT_LEN];
    memset(salt, 0, sizeof(salt));
    strncpy((char *)salt, source_dir,
            sizeof(salt) - 1 < strlen(source_dir) ? sizeof(salt) - 1 : strlen(source_dir));

    if (obfuse_derive_key(passphrase, salt, sizeof(salt),
                          state->key, OBFUSE_KEY_LEN) != 0) {
        OBFUSE_ERR("key derivation failed");
        memset(passphrase, 0, sizeof(passphrase));
        free(state->source_dir);
        free(state);
        free(fuse_argv);
        return 1;
    }

    memset(passphrase, 0, sizeof(passphrase));

    OBFUSE_LOG("source: %s", state->source_dir);
    OBFUSE_LOG("mounting...");

    int ret = fuse_main(fuse_argc, fuse_argv, &obfuse_ops, state);

    free(state->source_dir);
    memset(state->key, 0, OBFUSE_KEY_LEN);
    free(state);
    free(fuse_argv);

    return ret;
}
