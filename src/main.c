#include <stdio.h>
#include <string.h>
#include "encryption.h"

long int get_file_size(FILE *fp){
    fseek(fp, 0, SEEK_END);
    long int file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    return file_size;
}

int key_generation(FILE* key_file, unsigned char *my_key){
    if(get_file_size(key_file) != KEY_SIZE_IN_BYTES){
        printf("Incorrect length of key!\n");
        return -1;
    }

    for(int i = 0; i < KEY_SIZE_IN_BYTES; i++)
        fscanf(key_file, "%c", &my_key[i]);

    return 0;
}

int main(int argc, char* argv[]) {
    if(argc != 5){
        printf("Please, use format: %s <key> <input_file> <output_file> <mode>\n", argv[0]);
        return -1;
    }

    if(((argv[4][0] != ENCRYPTION_MODE) && (argv[4][0] != DECRYPTION_MODE)) || (strlen(argv[4]) != 1)){
        printf("Error value of mode!\n");
        return -1;
    }

    unsigned char key[KEY_SIZE_IN_BYTES] = {0};
    FILE *key_file;
    if((key_file = fopen(argv[1], "r")) == NULL){
        printf("Error when opening key file!\n");
        return -1;
    }
    if((key_generation(key_file, key)) != 0)
        return -1;
    fclose(key_file);
    printf("Key file opened");

    FILE *input, *output;
    if((input = fopen(argv[2], "r")) == NULL){
        printf("Error when opening input file\n");
        return -1;
    }
    printf("Input file opened\n");

    long int file_size = get_file_size(input);
    if(file_size == 0){
        printf("Your input file is empty!\n");
        fclose(input);
        return -1;
    }

    if((output = fopen(argv[3], "w")) == NULL){
        printf("Error when creating output file\n");
        fclose(input);
        return -1;
    }
    printf("Output file created\n");

    unsigned char text[BLOCK_SIZE_IN_BYTES];
    long int num_of_blocks;

    printf("Start encrypting/decrypting the file...\n");
    if(argv[4][0] == ENCRYPTION_MODE) {
        fprintf(output, "%ld", (BLOCK_SIZE_IN_BYTES - (file_size % BLOCK_SIZE_IN_BYTES)) % BLOCK_SIZE_IN_BYTES);
    }

    else{
        unsigned char elem;
        fscanf(input, "%c", &elem);
        file_size = file_size - 1 - (elem - 0x30);
    }

    if(file_size % BLOCK_SIZE_IN_BYTES == 0)
        num_of_blocks = file_size / BLOCK_SIZE_IN_BYTES;
    else
        num_of_blocks = (file_size / BLOCK_SIZE_IN_BYTES) + 1;

    subkeys ptr;
    key_expansion_blowfish(&ptr, key);
    printf("Subkey arrays (P and S) created\n");

    unsigned long text_left, text_right;
    for(int k = 0; k < num_of_blocks; k++){
        text_left = 0;
        text_right = 0;
        memset(text, 0, BLOCK_SIZE_IN_BYTES);

        for(int j = 0; j < BLOCK_SIZE_IN_BYTES && j < file_size; j++)
            fscanf(input, "%c", &text[j]);

        for(int i = 0; i < HALF_BLOCK_SIZE_IN_BYTES; i++){
            text_left = text_left | text[i];
            text_right = text_right | text[i + 4];
            if(i < 3) {
                text_left <<= 8;
                text_right <<= 8;
            }
        }

        if(argv[4][0] == ENCRYPTION_MODE)
            blowfish_encryption(&ptr, &text_left, &text_right);
        else
            blowfish_decryption(&ptr, &text_left, &text_right);

        for(int i = 3; i >= 0; i--){
            text[i] = text_left & 0xff;
            text_left >>= 8;
            text[i + 4] = text_right & 0xff;
            text_right >>= 8;
        }

        if(argv[4][0] == DECRYPTION_MODE){
            for(int i = 0; i < BLOCK_SIZE_IN_BYTES && (i + k * BLOCK_SIZE_IN_BYTES) < file_size; i++)
                fprintf(output, "%c", text[i]);
        }
        else{
            for(int i = 0; i < BLOCK_SIZE_IN_BYTES; i++)
                fprintf(output, "%c", text[i]);
        }
    }
    printf("Your file is encrypted/decrypted successfully!\n");
    fclose(input);
    fclose(output);
    return 0;
}
