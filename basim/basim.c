/*----------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes

FILE:   basim.c

Written By:  Team #3
     1- Mike Vance
     2- Jack Delano

Submitted on: 24OCT26
----------------------------------------------------------------------------*/

#include "../myCrypto.h"

int main(int argc, char *argv[])
{
    uint8_t digest[EVP_MAX_MD_SIZE];
    int i, fd_out, fd_ctrl, fd_data;
    size_t mdLen;
    FILE *log;

    char *developerName = "Mike Vance";

    printf("\nThis is Basim's code by '%s'.\n\n", developerName);

    // Get the FD arguments from the dispatcher & create  the log file

    if (argc != 3)
    {
        printf("Usage: basim <ctrlFD> <dataFD>\n");
        return EXIT_FAILURE;
    }

    fd_ctrl = atoi(argv[1]);
    fd_data = atoi(argv[2]);
    log = fopen("basim/logBasim.txt", "w");

    if (log == NULL)
    {
        perror("Basim: Could not create log file");
        return EXIT_FAILURE;
    }

    fprintf(log, "\nThis is Basim's code by '%s'.\n\n", developerName);

    fprintf(log, "Basim: I will receive digest from FD %d and file from FD %d\n",
            fd_ctrl, fd_data);

    // Create a blank bunny.cpy file with the proper access privileges
    //    and call fileDigesr() to compute its hash value in the digest[]
    fd_out = open("bunny.cpy", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd_out == -1)
    {
        fprintf(log, "Basim: Could not open output file\n");
        fclose(log);
        return EXIT_FAILURE;
    }

    // Use the fileDigest() function to:
    //    1) Receive the incoming data from the Data Pipe, and store a copy in bunny.cpy
    //    2) compute the hash value in the 'digest' array.
    fprintf(log, "Basim: Starting to receive incoming file and compute its digest\n");

    mdLen = fileDigest(fd_data, fd_out, digest);
    close(fd_out);
    if (mdLen == 0)
    {
        fprintf(log, "Basim: invalid file digest\n");
        fclose(log);
        return EXIT_FAILURE;
    }

    fprintf(log, "\nBasim: Here is locally-computed the digest of the incoming file:\n");
    BIO_dump_fp(log, digest, mdLen);

    // Get Amal's RSA public key from "basim/amal_pub_key.pem" which was generated
    // outside this program using the opessl tool
    EVP_PKEY *rsa_pubK = getRSAfromFile("basim/amal_pub_key.pem", 1);
    if (rsa_pubK == NULL)
    {
        fprintf(log, "Basim: Unable to read Amal's Public Key\n");
        fclose(log);
        return EXIT_FAILURE;
    }

    // Receive Amal's signature on this incoming file from the Control Pipe as a stream of bytes
    // First its length to allocate enough memory, then the signature itself
    size_t signature_len;
    uint8_t *signature = NULL;

    if (read(fd_ctrl, &signature_len, sizeof(size_t)) != sizeof(size_t))
    {
        fprintf(log, "Basim: Invalid signature length\n");
        EVP_PKEY_free(rsa_pubK);
        fclose(log);
        return EXIT_FAILURE;
    }

    signature = malloc(signature_len);
    if (!signature)
    {
        fprintf(log, "Basim: No memory to store the incoming signature from Amal\n");
        EVP_PKEY_free(rsa_pubK);
        fclose(log);
        return EXIT_FAILURE;
    }

    if (read(fd_ctrl, signature, signature_len) != signature_len)
    {
        fprintf(log, "Basim: Unable to read Amal's signature\n");
        EVP_PKEY_free(rsa_pubK);
        free(signature);
        fclose(log);
        return EXIT_FAILURE;
    }

    fprintf(log, "\nBasim: I received the following signature from Amal:\n");
    BIO_dump_fp(log, signature, signature_len);

    // Verify, using Amal's public key, the incoming signature is valid given
    // the locally-calculated digest

    fprintf(log, "\nBasim: I found that Amal's signature is ");
    if (pubKeyVerify(signature, signature_len, rsa_pubK, digest, mdLen))
        fprintf(log, "VALID\n");
    else
        fprintf(log, "INVALID\n");

    // Close all files & Free all dynamically allocated objects
    EVP_PKEY_free(rsa_pubK);
    free(signature);
    fclose(log);

    return EXIT_SUCCESS;
}
