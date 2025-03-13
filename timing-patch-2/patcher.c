#include <stdio.h>
#include <stdlib.h>

void hexdump(const void *data, size_t size)
{
    const unsigned char *p = data;
    for (size_t i = 0; i < size; i++)
    {
        printf("%02x ", p[i]);
    }
    printf("\n");
}

void patch_file(const char *thefile, const char *patch_file, size_t offset)
{
    //open the file for patching
    FILE *file = fopen(thefile, "r+b");
    if (!file)
    {
        perror("Failed to open file for patching");
        exit(EXIT_FAILURE);
    }
    //read the entire patch file
    FILE *patchfile = fopen(patch_file, "rb");
    if (!patchfile)
    {
        perror("Failed to open patch file");
        fclose(file);
        exit(EXIT_FAILURE);
    }
    fseek(patchfile, 0, SEEK_END);
    size_t patchsize = ftell(patchfile);
    fseek(patchfile, 0, SEEK_SET);
    unsigned char *patch = malloc(patchsize);
    if (!patch)
    {
        perror("Memory allocation failed");
        fclose(patchfile);
        fclose(file);
        exit(EXIT_FAILURE);
    }
    if (fread(patch, 1, patchsize, patchfile) != patchsize)
    {
        perror("Error reading patch file");
        free(patch);
        fclose(patchfile);
        fclose(file);
        exit(EXIT_FAILURE);
    }
    fclose(patchfile);
    unsigned char *temp = malloc(patchsize);
    //goto the offset, read the current data, hexdump
    fseek(file, offset, SEEK_SET);
    if (fread(temp, 1, patchsize, file) != patchsize)
    {
        perror("Error reading file for patching");
        free(patch);
        free(temp);
        fclose(file);
        exit(EXIT_FAILURE);
    }
    printf("Before patching:\n");
    hexdump(temp, patchsize);
    //write the patch data
    fseek(file, offset, SEEK_SET);
    if (fwrite(patch, 1, patchsize, file) != patchsize)
    {
        perror("Error writing patch data");
        free(patch);
        free(temp);
        fclose(file);
        exit(EXIT_FAILURE);
    }
    //read the data again, hexdump
    fseek(file, offset, SEEK_SET);
    if (fread(temp, 1, patchsize, file) != patchsize)
    {
        perror("Error reading file for patching");
        free(patch);
        free(temp);
        fclose(file);
        exit(EXIT_FAILURE);
    }
    printf("After patching:\n");
    hexdump(temp, patchsize);
    free(patch);
    free(temp);
    fclose(file);
    
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input file> <output file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    FILE *input = fopen(argv[1], "rb");
    if (!input) {
        perror("Failed to open input file");
        return EXIT_FAILURE;
    }

    FILE *output = fopen(argv[2], "wb");
    if (!output) {
        perror("Failed to open output file");
        fclose(input);
        return EXIT_FAILURE;
    }

    char buffer[4096];
    //copy the input file to the output file
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), input)) > 0) {
        fwrite(buffer, 1, bytes_read, output);
    }    

    fclose(input);
    fclose(output);
    patch_file(argv[2], "patch1.bin", 0x9149F);
    patch_file(argv[2], "patch2.bin", 0x7f0e);
    patch_file(argv[2], "patch3.bin", 0x466ea);
    patch_file(argv[2], "patch4.bin", 0x9650);    


    return EXIT_SUCCESS;
}