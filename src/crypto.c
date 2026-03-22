#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

int obfuse_derive_key(const char *passphrase, const uint8_t *salt,
                      size_t salt_len, uint8_t *key_out, size_t key_len)
{
    if (PKCS5_PBKDF2_HMAC(passphrase, (int)strlen(passphrase),
                           salt, (int)salt_len,
                           OBFUSE_PBKDF2_ITER,
                           EVP_sha256(),
                           (int)key_len, key_out) != 1) {
        return -1;
    }
    return 0;
}

int obfuse_encrypt(const uint8_t *key, const uint8_t *iv,
                   uint8_t *buf, size_t len, off_t offset)
{
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t ctr_iv[OBFUSE_IV_LEN];
    int outlen = 0;
    int ret = -1;

    /* Adjust the IV/counter for the given byte offset.
     * AES-CTR increments the counter every 16 bytes. We advance the
     * counter by (offset / 16) blocks and then discard (offset % 16)
     * bytes from the keystream to align with the file position. */

    memcpy(ctr_iv, iv, OBFUSE_IV_LEN);

    /* Add block offset to the 128-bit counter (big-endian increment) */
    uint64_t block_offset = (uint64_t)offset / OBFUSE_IV_LEN;
    for (int i = OBFUSE_IV_LEN - 1; i >= 0 && block_offset > 0; i--) {
        uint64_t sum = (uint64_t)ctr_iv[i] + (block_offset & 0xFF);
        ctr_iv[i] = (uint8_t)(sum & 0xFF);
        block_offset = (block_offset >> 8) + (sum >> 8);
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto out;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, ctr_iv) != 1)
        goto out;

    /* Discard partial-block keystream bytes to align to byte offset */
    size_t skip = (size_t)(offset % OBFUSE_IV_LEN);
    if (skip > 0) {
        uint8_t discard[OBFUSE_IV_LEN];
        uint8_t zeros[OBFUSE_IV_LEN] = {0};
        if (EVP_EncryptUpdate(ctx, discard, &outlen, zeros, (int)skip) != 1)
            goto out;
    }

    if (EVP_EncryptUpdate(ctx, buf, &outlen, buf, (int)len) != 1)
        goto out;

    ret = 0;

out:
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int obfuse_decrypt(const uint8_t *key, const uint8_t *iv,
                   uint8_t *buf, size_t len, off_t offset)
{
    /* AES-CTR decryption is identical to encryption */
    return obfuse_encrypt(key, iv, buf, len, offset);
}

int obfuse_random_bytes(uint8_t *buf, size_t len)
{
    if (RAND_bytes(buf, (int)len) != 1)
        return -1;
    return 0;
}
