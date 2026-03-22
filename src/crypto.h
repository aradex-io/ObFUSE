#ifndef OBFUSE_CRYPTO_H
#define OBFUSE_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define OBFUSE_KEY_LEN    32  /* AES-256 */
#define OBFUSE_IV_LEN     16  /* AES block size */
#define OBFUSE_SALT_LEN   16
#define OBFUSE_PBKDF2_ITER 100000

/**
 * Derive an encryption key from a passphrase using PBKDF2-HMAC-SHA256.
 * Returns 0 on success, -1 on failure.
 */
int obfuse_derive_key(const char *passphrase, const uint8_t *salt,
                      size_t salt_len, uint8_t *key_out, size_t key_len);

/**
 * Encrypt a buffer in place using AES-256-CTR.
 * The IV should be unique per file. offset allows seeking into the CTR stream.
 * Returns 0 on success, -1 on failure.
 */
int obfuse_encrypt(const uint8_t *key, const uint8_t *iv,
                   uint8_t *buf, size_t len, off_t offset);

/**
 * Decrypt a buffer in place using AES-256-CTR.
 * Symmetric to obfuse_encrypt (CTR mode encryption == decryption).
 * Returns 0 on success, -1 on failure.
 */
int obfuse_decrypt(const uint8_t *key, const uint8_t *iv,
                   uint8_t *buf, size_t len, off_t offset);

/**
 * Generate cryptographically secure random bytes.
 * Returns 0 on success, -1 on failure.
 */
int obfuse_random_bytes(uint8_t *buf, size_t len);

#endif /* OBFUSE_CRYPTO_H */
