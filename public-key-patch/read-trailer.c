#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <nettle/yarrow.h>
#include <assert.h>
#include <stdint.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

const char *PRIVATE_KEY_PEM =
    "-----BEGIN PRIVATE KEY-----\n"
    "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\n"
    "sOKmXagzbDe1FDdgyr5b/0WEv0xq\n"
    "-----END PRIVATE KEY-----\n";


uint32_t swap32(uint32_t a1)
{
    return (a1 >> 8 << 16) & 0xFF0000 | (a1 << 8 >> 16) & 0xFF00 | (a1 >> 24) | (a1 << 24);
}

void inverse_swap32_buffer(uint32_t *buffer, size_t size)
{
    for (size_t i = 0; i < size / 4; i++)
    {
        buffer[i] = swap32(buffer[i]); // Applying swap32 again to reverse
    }
}

void hexdump(const char *title, uint8_t *data, int len)
{
    printf("%s: ", title);
    for (int i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
    printf("\n");
}

void hexprint(uint8_t *data, int len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf(" ");
}

void split_back(uint64_t a1,            // original byte length of first array
                uint64_t a3,            // original byte length of second array
                const uint32_t *merged, // merged (and swapped) array
                uint32_t *out1,         // output: first array (unswapped)
                uint32_t *out2)         // output: second array (unswapped)
{
    // Compute word counts for each array.
    size_t count1 = a1 >> 2;
    size_t count2 = a3 >> 2;
    size_t total = count1 + count2;

    // Determine interleaving pattern (must match merge_and_swap):
    // If a1 is 32 bytes (i.e. 8 words) then every 3rd word starting at index 2 came from the second array.
    // Otherwise, every 2nd word starting at index 1 came from the second array.
    int next_arr2_index, arr2_step;
    if (a1 == 32)
    {
        next_arr2_index = 2;
        arr2_step = 3;
    }
    else
    {
        next_arr2_index = 1;
        arr2_step = 2;
    }

    size_t index1 = 0, index2 = 0;
    for (size_t i = 0; i < total; i++)
    {
        // If this position originally came from arr2, recover it there.
        if ((int)i == next_arr2_index)
        {
            out2[index2++] = swap32(merged[i]);
            next_arr2_index += arr2_step;
        }
        else
        {
            // Otherwise, it came from arr1.
            out1[index1++] = swap32(merged[i]);
        }
    }
}



void gen_key(uint64_t t, char *dest)
{

    struct yarrow256_ctx ctx;
    yarrow256_init(&ctx, 0, NULL);
    char seed[32];
    snprintf(seed, sizeof(seed), "%lld", t);

    yarrow256_seed(&ctx, strlen(seed), seed);
    char buffer[32];
    yarrow256_random(&ctx, 32, buffer);   
    for (int i =0; i < sizeof(buffer); i++) {
        printf("%02x", (unsigned char )(buffer[i]));
    }
    memcpy(dest, buffer, 32);
    printf("\n");
}


static uint64_t *timestamps;
static char **timestamp_random;
static int timestamp_count;

int readlog(char *logfile)
{
    //read log file
    FILE *fp = fopen(logfile, "rb");
    if (fp == NULL) {
        printf("Error: Unable to open file %s\n", logfile);
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buffer = malloc(fsize + 1);
    if (buffer == NULL) {
        printf("Error: Unable to allocate memory\n");
        return 1;
    }
    fread(buffer, fsize, 1, fp);
    fclose(fp);
    uint64_t *t = (uint64_t *)buffer;
    for (int i = 0; i < fsize/sizeof(uint64_t); i++) {            
        if (t[i] < 1700000000000000000) {
            break;
        }
        if (t[i] > 1800000000000000000) {
            break;
        }
        printf("t = %lld: ", t[i]);
        char *random = (char *)malloc(32);
        gen_key(t[i], random);
        timestamp_random = (char **)realloc(timestamp_random, (i+1)*sizeof(char *));
        timestamp_random[i] = random;
        timestamp_count = i + 1;
    }
    timestamps = t;
    return 0;
}

uint64_t search_timestamp(char *data, int len)
{        
        for (int i = 0; i < timestamp_count; i++) {
                if (memcmp(timestamp_random[i], data, len)==0) {
                        return timestamps[i];
                }                
        }
        return 0;
}

int main(int argc, char *argv[])
{

    if (argc > 1)
    {
        if (argc > 2) {
                readlog(argv[2]);
        }
        const char *input_filename = argv[1];
        FILE *input_file = fopen(input_filename, "rb");
        if (!input_file)
        {
            perror("Error opening input file");
            return EXIT_FAILURE;
        }

        fseek(input_file, 0, SEEK_END);
        long file_size = ftell(input_file);
        if (file_size < 512)
        {
            printf("File is smaller than 512 bytes, processing entire file.\n");
            file_size = 512;
        }

        fseek(input_file, file_size - 512, SEEK_SET);
        uint8_t buffer[512];
        size_t bytes_read = fread(buffer, 1, 512, input_file);
        fclose(input_file);

        if (bytes_read == 0)
        {
            perror("Error reading file");
            return EXIT_FAILURE;
        }

        int inlen = 512;

        inverse_swap32_buffer((uint32_t *)buffer, bytes_read);

        BIO *bio = BIO_new_mem_buf(PRIVATE_KEY_PEM, -1);
        if (!bio)
        {
            perror("Error creating BIO");
            return EXIT_FAILURE;
        }

        RSA *rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (!rsa)
        {
            printf("Error reading private key\n");
            return EXIT_FAILURE;
        }

        unsigned char *encrypted = buffer;
        unsigned char *decrypted = malloc(RSA_size(rsa));
        if (!decrypted)
        {
            printf("Error allocating memory\n");
            return EXIT_FAILURE;
        }
        int decrypted_len = RSA_private_decrypt(inlen, encrypted, decrypted, rsa, RSA_PKCS1_PADDING);
        if (decrypted_len == -1)
        {
            printf("Error decrypting\n");
            return EXIT_FAILURE;
        }
        RSA_free(rsa);

        uint8_t chacha20_key[32];
        uint8_t chacha20_nonce[16];
        uint8_t *start_chacha = (uint8_t *)decrypted + 11;
        split_back(32, 16, (uint32_t *)start_chacha, (uint32_t *)chacha20_key, (uint32_t *)chacha20_nonce);
        hexdump("chacha20_key", chacha20_key, 32);
        uint64_t t1 = search_timestamp(chacha20_key, 32);
        if (t1 != 0) {
                printf("T1 = %lld\n\n", t1);
        }

        hexdump("chacha20_nonce", chacha20_nonce, 16);
        uint64_t t2 = search_timestamp(chacha20_nonce, 16);
        if (t2 != 0) {
                printf("T2 = %lld\n\n", t2);
        }


        uint8_t *start_kcipher2 = (uint8_t *)decrypted + 59;
        uint8_t kcipher2_key[16];
        uint8_t kcipher2_iv[16];
        split_back(16, 16, (uint32_t *)start_kcipher2, (uint32_t *)kcipher2_key, (uint32_t *)kcipher2_iv);
        hexdump("kcipher2_key", kcipher2_key, 16);
        uint64_t t3 = search_timestamp(kcipher2_key, 16);
        if (t3 != 0) {
                printf("T3 = %lld\n\n", t3);
        }


        hexdump("kcipher2_iv", kcipher2_iv, 16);
        uint64_t t4 = search_timestamp(kcipher2_iv, 16);
        if (t4 != 0) {
                printf("T4 = %lld\n", t4);
        }

        if (timestamp_count > 0) {
                printf("\n");
                printf("T4 - T3 = %d\n", t4 - t3);
                printf("T3 - T1 = %d\n", t3 - t1);
                printf("T2 - T1 = %d\n", t2 - t1);
        }

    }
    else
    {
        printf("No arguments provided\n");
    }
}
