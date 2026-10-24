/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c

Written By:  Team #3
     1- Mike Vance
     2- Jack Delano

Submitted on: 24OCT26
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//***********************************************************************
// pLAB-01
//***********************************************************************

void handleErrors(char *msg)
{
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    abort();
}

//-----------------------------------------------------------------------------
// Encrypt the plaint text stored at 'pPlainText' into the
// caller-allocated memory at 'pCipherText'
// Caller must allocate sufficient memory for the cipher text
// Returns size of the cipher text in bytes

// For the following Encryption/Decryption,
// use a 256-bit key and AES in CBC mode (with a 128-bit IV)
// Ensure the (key,IV) being used match the specified algorithm

unsigned encrypt(uint8_t *pPlainText, unsigned plainText_len,
                 const uint8_t *key, const uint8_t *iv, uint8_t *pCipherText)
{
    int status;

    int len = 0; // EVP_EncryptUpdate expects an int, not unsigned
    unsigned encryptedLen = 0;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors("encrypt: failed to creat CTX");

    // Initialise the encryption operation.
    status = EVP_EncryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptInit_ex");

    // Call EncryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular encryption
    status = EVP_EncryptUpdate(ctx, pCipherText, &len, pPlainText, plainText_len);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptUpdate");
    encryptedLen += len;

    // If additional ciphertext may still be generated,
    // the pCipherText pointer must be first advanced forward
    pCipherText += len;

    // Finalize the encryption.
    status = EVP_EncryptFinal_ex(ctx, pCipherText, &len);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptFinal_ex");
    encryptedLen += len; // len could be 0 if no additional cipher text was generated

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return encryptedLen;
}

//-----------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the
// caller-allocated memory at 'pDecryptedText'
// Caller must allocate sufficient memory for the decrypted text
// Returns size of the decrypted text in bytes

unsigned decrypt(uint8_t *pCipherText, unsigned cipherText_len,
                 const uint8_t *key, const uint8_t *iv, uint8_t *pDecryptedText)
{
    int status;
    int len = 0; // changed for the same reason as above.
    unsigned decryptedLen = 0;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors("decrypt: failed to creat CTX");

    // Initialise the decryption operation.
    status = EVP_DecryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptInit_ex");

    // Call DecryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular decryption
    status = EVP_DecryptUpdate(ctx, pDecryptedText, &len, pCipherText, cipherText_len);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptUpdate");
    decryptedLen += len;

    // If additionl decrypted text may still be generated,
    // the pDecryptedText pointer must be first advanced forward
    pDecryptedText += len;

    // Finalize the decryption.
    status = EVP_DecryptFinal_ex(ctx, pDecryptedText, &len);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptFinal_ex");
    decryptedLen += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return decryptedLen;
}

//-----------------------------------------------------------------------------

static unsigned char plaintext[PLAINTEXT_LEN_MAX], // Temporarily store plaintext
    ciphertext[CIPHER_LEN_MAX],                    // Temporarily store outcome of encryption
    decryptext[DECRYPTED_LEN_MAX];                 // Temporarily store decrypted text

// above arrays being static to resolve runtime stack size issue.
// However, that makes the code non-reentrant for multithreaded application

//***********************************************************************
// PA-01
//***********************************************************************

int encryptFile(int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv)
{
    int status;

    int total = 0; // the number of bytes encrypted and written to fd_out
    int len = 0;   // EVP_EncryptUpdate expects an int, not unsigned

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors("encryptFile: failed to creat CTX");

    // Initialise the encryption operation.
    status = EVP_EncryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors("encryptFile: failed to EncryptInit_ex");

    /* loop over each block of PLAINTEXT_LEN_MAX size */
    while (1)
    {
        // call read and handle EOF or errors
        ssize_t n = read(fd_in, plaintext, PLAINTEXT_LEN_MAX);

        if (n < 0)
        {
            perror("encryptFile: read() failed");
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        if (n == 0)
            break; // reached end of file

        // call EncryptUpdate on the newly read block
        status = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, n);
        if (status != 1)
            handleErrors("encryptFile: failed to EncryptUpdate");

        // write ciphertext to file and add len to total if successful
        if (write(fd_out, ciphertext, len) != len)
        {
            perror("encryptFile: write() failed");
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        total += len;
    }

    /* finialize encryption */
    status = EVP_EncryptFinal_ex(ctx, ciphertext, &len);
    if (status != 1)
        handleErrors("encryptFIle: failed to EncryptFinal_ex");

    if (write(fd_out, ciphertext, len) != len)
    {
        perror("encryptFile: write() failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total += len;

    /* clean up and return */
    EVP_CIPHER_CTX_free(ctx);

    return total;
}

//-----------------------------------------------------------------------------

int decryptFile(int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv)
{
    int status;

    int total = 0; // the number of bytes decrypted and written to fd_out
    int len = 0;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors("decryptFile: failed to creat CTX");

    // Initialise the decryption operation.
    status = EVP_DecryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors("decryptFile: failed to DecryptInit_ex");

    /* loop over each block of CIPHER_LEN_MAX size */
    while (1)
    {
        // call read and handle EOF or errors
        ssize_t n = read(fd_in, ciphertext, CIPHER_LEN_MAX);

        if (n < 0)
        {
            perror("decryptFile: read() failed");
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        if (n == 0)
            break; // reached end of file

        // call DecryptUpdate on the newly read block
        status = EVP_DecryptUpdate(ctx, decryptext, &len, ciphertext, n);
        if (status != 1)
            handleErrors("decryptFile: failed to DecryptUpdate");

        // write decrypted text to file and add len to total if successful
        if (write(fd_out, decryptext, len) != len)
        {
            perror("decryptFile: write() failed");
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        total += len;
    }

    /* finialize decryption */
    status = EVP_DecryptFinal_ex(ctx, decryptext, &len);
    if (status != 1)
        handleErrors("decryptFile: failed to DecryptFinal_ex");

    if (write(fd_out, decryptext, len) != len)
    {
        perror("decryptFile: write() failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total += len;

    /* clean up and return */
    EVP_CIPHER_CTX_free(ctx);

    return total;
}

//***********************************************************************
// pLAB-02
//***********************************************************************

EVP_PKEY *getRSAfromFile(char *filename, int public)
{
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL)
    {
        fprintf(stderr, "getRSAfromFile: Unable to open RSA key file %s \n", filename);
        return NULL;
    }

    EVP_PKEY *key = EVP_PKEY_new();
    if (public)
        key = PEM_read_PUBKEY(fp, &key, NULL, NULL);
    else
        key = PEM_read_PrivateKey(fp, &key, NULL, NULL);

    fclose(fp);

    return key;
}

//***********************************************************************
// PA-02
//***********************************************************************
// Sign the 'inData' array into the 'sig' array using the private 'privKey'
// 'inLen' is the size of the input array in bytes.
// the '*sig' pointer will be allocated memory large enough to store the signature
// report the actual length in bytes of the result in 'sigLen'
//
// Returns:
//    1 on success, or 0 on ANY REASON OF FAILURE

int privKeySign(uint8_t **sig, size_t *sigLen, EVP_PKEY *privKey,
                uint8_t *inData, size_t inLen)
{
    // TODO (Amal side): implement
    //
    // Guard against incoming NULL pointers
    //
    // Create and Initialize a context for RSA private-key signing
    // EVP_PKEY_CTX_new( );
    // EVP_PKEY_sign_init( )
    // EVP_PKEY_CTX_set_rsa_padding( use RSA_PKCS1_PADDING )
    //
    // Determine how big the size of the signature could be
    // EVP_PKEY_sign( ) with a NULL output buffer
    //
    // Next allocate memory for the signature
    //
    // Now, actually sign the inData using EVP_PKEY_sign( )
    //
    // EVP_PKEY_CTX_free( ctx ) on success AND on every failure path

    return 0;
}

//-----------------------------------------------------------------------------
// Verify that the provided signature in 'sig' when decrypted using 'pubKey'
// matches the data in 'data'
// Returns 1 if they match, 0 otherwise

int pubKeyVerify(uint8_t *sig, size_t sigLen, EVP_PKEY *pubKey,
                 uint8_t *data, size_t dataLen)
{
    // TODO (Basim side): implement
    //
    // Guard against incoming NULL pointers
    //
    // Create and Initialize a context for RSA public-key signature verification
    // EVP_PKEY_CTX_new( );
    // EVP_PKEY_verify_init( )
    // EVP_PKEY_CTX_set_rsa_padding( use RSA_PKCS1_PADDING )
    //
    // Verify the signature vs the incoming data using EVP_PKEY_verify( )
    //
    // Free any dynamically-allocated objects

    return 0;
}

//-----------------------------------------------------------------------------
// Read all the incoming data stream from the 'fd_in' file descriptor
// Apply the HASH_ALGORITHM() to compute the hash value of this incoming data into the array 'digest'
// If the file descriptor 'fd_out' is > 0, also write a copy of the incoming data stream file to 'fd_out'
// Returns actual size in bytes of the computed digest, or 0 on failure

size_t fileDigest(int fd_in, int fd_out, uint8_t *digest)
{
    unsigned int mdLen = 0; // EVP_DigestFinal expects an unsigned int

    if (!digest)
    {
        fprintf(stderr, "fileDigest: received a NULL digest pointer\n");
        return 0;
    }

    /* Create and initialise the hashing context */
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    if (!mdCtx)
    {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        return 0;
    }

    if (EVP_DigestInit(mdCtx, HASH_ALGORITHM()) != 1)
    {
        fprintf(stderr, "EVP_DigestInit failed\n");
        EVP_MD_CTX_destroy(mdCtx);
        return 0;
    }

    /* loop over each block of PLAINTEXT_LEN_MAX size until end-of-file */
    while (1)
    {
        // call read and handle EOF or errors
        ssize_t n = read(fd_in, plaintext, PLAINTEXT_LEN_MAX);

        if (n < 0)
        {
            perror("fileDigest: read() failed");
            EVP_MD_CTX_destroy(mdCtx);
            return 0;
        }
        if (n == 0)
            break; // reached end of file

        // add the newly read block to the running hash
        if (EVP_DigestUpdate(mdCtx, plaintext, n) != 1)
        {
            fprintf(stderr, "EVP_DigestUpdate failed\n");
            EVP_MD_CTX_destroy(mdCtx);
            return 0;
        }

        // forward a copy of the block if an output descriptor was given
        if (fd_out > 0 && write(fd_out, plaintext, n) != n)
        {
            perror("fileDigest: write() failed");
            EVP_MD_CTX_destroy(mdCtx);
            return 0;
        }
    }

    /* finalize the hash */
    if (EVP_DigestFinal(mdCtx, digest, &mdLen) != 1)
    {
        fprintf(stderr, "EVP_DigestFinal failed\n");
        EVP_MD_CTX_destroy(mdCtx);
        return 0;
    }

    /* clean up and return */
    EVP_MD_CTX_destroy(mdCtx);

    return mdLen;
}