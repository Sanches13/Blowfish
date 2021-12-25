#include "tables.h"

#define BLOCK_SIZE_IN_BYTES 8
#define HALF_BLOCK_SIZE_IN_BYTES 4
#define KEY_SIZE_IN_BYTES 32
#define ENCRYPTION_MODE '1'
#define DECRYPTION_MODE '2'

typedef struct{
    unsigned long p[18];
    unsigned long s[4][256];
}subkeys;

void swap(unsigned long *first, unsigned long *second){
    unsigned long temp = *first;
    *first = *second;
    *second = temp;
}

unsigned long F_function(subkeys *ptr, unsigned long input){
    unsigned long temp = 0;
    unsigned short x[HALF_BLOCK_SIZE_IN_BYTES] = {0};
    for(int i = 3; i >= 0; i--){
        x[i] = input & 0xff;
        input = input >> 8;
    }

    temp = ptr->s[0][x[0]] + ptr->s[1][x[1]];
    temp = temp ^ ptr->s[2][x[2]];
    temp = temp + ptr->s[3][x[3]];
    return temp;
}

void blowfish_encryption(subkeys *ptr, unsigned long *left, unsigned long *right){
    unsigned long left_block = *left, right_block = *right;
    for (int i = 0; i < 16; i++){
        left_block = left_block ^ ptr->p[i];
        right_block = right_block ^ F_function(ptr, left_block);
        swap(&left_block, &right_block);
    }

    swap(&left_block, &right_block);

    right_block = right_block ^ ptr->p[16];
    left_block = left_block ^ ptr->p[17];

    *left = left_block;
    *right = right_block;
}

void key_expansion_blowfish(subkeys *ptr, unsigned char key[KEY_SIZE_IN_BYTES]){
    unsigned long left_block = 0, right_block = 0, temp = 0;
    for (int i = 0; i < 18; i++)
        ptr->p[i] = initial_p[i];

    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 256; ++j)
            ptr->s[i][j] = initial_s[i][j];

    for (int i = 0, current_len = 0; i < 18; i++){
        for (int j = 0; j < 4; j++, current_len++) {
            temp = temp << 8;
            temp = temp | key[current_len % KEY_SIZE_IN_BYTES];
        }
        ptr->p[i] = ptr->p[i] ^ temp;
    }

    for (int i = 0; i < 18; i += 2){
        blowfish_encryption(ptr, &left_block, &right_block);
        ptr->p[i] = left_block;
        ptr->p[i+1] = right_block;
    }

    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 256; j += 2){
            blowfish_encryption(ptr, &left_block, &right_block);
            ptr->s[i][j] = left_block;
            ptr->s[i][j+1] = right_block;
        }
    }
}

void blowfish_decryption(subkeys *ptr, unsigned long *left, unsigned long *right){
    unsigned long left_block = *left, right_block = *right;

    for (int i = 17; i > 1; i--){
        left_block = left_block ^ ptr->p[i];
        right_block = right_block ^ F_function(ptr, left_block);
        swap(&left_block, &right_block);
    }

    swap(&left_block, &right_block);

    left_block = left_block ^ ptr->p[0];
    right_block = right_block ^ ptr->p[1];

    *left = left_block;
    *right = right_block;
}

