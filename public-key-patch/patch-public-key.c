#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//note: this is for patching public key
/*
 * DER must use legacy format 
 *
 * openssl pkey -inform PEM -pubin -in public.pem -outform DER -out public.der
 * openssl rsa -in public.der -inform DER -pubin -RSAPublicKey_out -outform DER -out pub2.der
 */

#define PATCH_ADDRESS 0x02a76c0

#define PAD_SIZE 4096

void read_file(const char *filename, unsigned char **data, size_t *size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    rewind(file);
    *data = malloc(*size);
    if (!*data) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    fread(*data, 1, *size, file);
    fclose(file);
}

void write_file(const char *filename, unsigned char *data, size_t size) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }
    fwrite(data, 1, size, file);
    fclose(file);
}

void patch_elf(const char *input_elf, const char *public_der, const char *output_elf) {
    unsigned char *elf_data, *der_data;
    size_t elf_size, der_size;
    
    read_file(input_elf, &elf_data, &elf_size);
    read_file(public_der, &der_data, &der_size);

    if (der_size != 526) {
        printf("Invalid DER size\n"); //if it is not 526, we need to patch the length, and we don't need that for now
        return;
    }
    
    unsigned char padded_der[PAD_SIZE] = {0};
    memcpy(padded_der, der_data, der_size < PAD_SIZE ? der_size : PAD_SIZE);
    free(der_data);
    
    if (PATCH_ADDRESS + PAD_SIZE > elf_size) {
        fprintf(stderr, "Patch address out of bounds\n");
        exit(EXIT_FAILURE);
    }
    
    memcpy(elf_data + PATCH_ADDRESS, padded_der, PAD_SIZE);
    
    write_file(output_elf, elf_data, elf_size);
    free(elf_data);
    
    printf("Patched %s and saved to %s\n", input_elf, output_elf);
}

int main(int argc, char *argv[]) {
    //read arguments from the command line
    if (argc != 4) {
        printf("Usage: %s <input_elf> <public_key.der> <output_elf>\n", argv[0]);
        return EXIT_FAILURE;
    }
    patch_elf(argv[1], argv[2], argv[3]);
    return 0;
}

