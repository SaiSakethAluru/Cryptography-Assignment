#include <stdio.h>
#include <stdlib.h>
#include <math.h>

// function prototype declarations
int** initialise_column_matrix(char* init_text);
int** decrypt(int** ciphertext_matrix, int** key_matrix);
void sub_matrix(int** matrix);
int** add_round_key(int** plaintext_matrix,int** key_matrix);
int** get_next_key(int** key_matrix,int round);
int** inverse_mix_column(int** matrix);
void shift_row(int** matrix);
void right_shift(int* array);
void print_matrix(int** matrix, int rows,int cols);
void sub_byte(int* array);
void left_shift(int* array);

// AES SBox for encryption and key generation algorithm
int sbox[16][16] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
  {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
  {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
  {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
  {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
  {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
  {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
  {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
  {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
  {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
  {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
  {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
  {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
  {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
  {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
  {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} };

// AES inverse sbox for decryption
int inverse_sbox[16][16] = {
    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};

// round constants used in key generation algorithm
int round_constant[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

int main()
{
    char ciphertext_ascii[17],key_ascii[17];
    printf("Enter cipher text of 4x4 hex number matrix to decrypt: \n");
    char c;
    int i,j;
    int** ciphertext_matrix = (int**)malloc(sizeof(int*)*4);
    int** plaintext_matrix = (int**)malloc(sizeof(int*)*4);
    int** key_matrix = (int**)malloc(sizeof(int*)*4);
    for(i=0;i<4;i++){
        plaintext_matrix[i] = (int*) malloc(sizeof(int)*4);
        ciphertext_matrix[i] = (int*) malloc(sizeof(int)*4);
        key_matrix[i] = (int*)malloc(sizeof(int)*4);
    }
    for(i=0;i<4;i++){
        for(j=0;j<4;j++){
            scanf("%x",&ciphertext_matrix[i][j]);
        }
    }
    printf("Enter the key of 16 characters for decryption: ");
    c = getchar();  
    for(i=0;i<16;i++){
        c = getchar();
        if(c!='\n' || c!='\0')
            key_ascii[i] = c;

    }
    key_ascii[16] = '\0';
    printf("key = %s\n",key_ascii);
    key_matrix = initialise_column_matrix(key_ascii);
    plaintext_matrix = decrypt(ciphertext_matrix,key_matrix);
    printf("\n\n==================\nPlaintext Matrix :\n");
    print_matrix(plaintext_matrix,4,4);
    printf("\n\n==================\nPlaintext Ascii :\n"); 
    for(i=0;i<4;i++){
        for(j=0;j<4;j++){
            printf("%c",(char)plaintext_matrix[j][i] );
        }
    }
    printf("\n");
    return 0;
}

// convert given string of key text to 4x4 matrix form
int** initialise_column_matrix(char* init_text)
{
    int i,j;
    int** matrix = (int**) malloc(sizeof(int*)*4);
    for(i=0;i<4;i++){
        matrix[i] = (int*)malloc(sizeof(int)*4);
    }
    for(i=0;i<4;i++){
        for(j=0;j<4;j++){
            matrix[j][i] = (int)init_text[4*i+j];
        }
    }
    return matrix;
}

// one round decryption function
int** decrypt(int** ciphertext_matrix, int** key_matrix)
{
    int i;
    int** plaintext_matrix = (int**)malloc(sizeof(int*)*4);
    int** next_key = (int**)malloc(sizeof(int*)*4);
    for(i=0;i<4;i++){
        plaintext_matrix[i] = (int*)malloc(sizeof(int)*4);
        next_key[i] = (int*)malloc(sizeof(int)*4);
    }
    next_key = get_next_key(key_matrix,0);
    plaintext_matrix = add_round_key(ciphertext_matrix,next_key);
    plaintext_matrix = inverse_mix_column(plaintext_matrix);
    shift_row(plaintext_matrix);
    sub_matrix(plaintext_matrix);
    plaintext_matrix = add_round_key(plaintext_matrix,key_matrix);
}

// substitute each element of matrix with corresponding value from sbox
void sub_matrix(int** matrix)
{
    int i,j;
    for(i=0;i<4;i++){
        for(j=0;j<4;j++){
            int col = matrix[i][j]%16;
            int row = matrix[i][j]/16;
            matrix[i][j] = inverse_sbox[row][col];
        }
    }
}

// takes intermediate plaintext and key matrices and does element wise xor
int** add_round_key(int** plaintext_matrix,int** key_matrix)
{
    int i,j;
    int** ciphertext_matrix = (int**) malloc(sizeof(int*)*4);
    for(i=0;i<4;i++){
        ciphertext_matrix[i] = (int*)malloc(sizeof(int)*4);
    }
    for(i=0;i<4;i++){
        for(j=0;j<4;j++){
            ciphertext_matrix[i][j] = plaintext_matrix[i][j] ^ key_matrix[i][j];
        }
    }
    return ciphertext_matrix;
}

// takes current key matrix and round number and return key matrix for next round
int** get_next_key(int** key_matrix,int round)
{
    int i,j;
    int** new_key = (int**)malloc(sizeof(int*)*4);
    for(i=0;i<4;i++){
        new_key[i] = (int*)malloc(sizeof(int)*4);
    }
    int temp[4];
    for(i=0;i<4;i++){
        temp[i] = key_matrix[i][3];
    }
    left_shift(temp);
    sub_byte(temp);
    temp[0] = temp[0]^round_constant[round];
    for(i=0;i<4;i++){
        for(j=0;j<4;j++){
            new_key[j][i] = temp[j]^key_matrix[j][i];
        }
        for(j=0;j<4;j++){
            temp[j] = new_key[j][i];
        }
    }
    return new_key;
}

// inverse of mix column function of AES
int** inverse_mix_column(int** matrix)
{
    int i,j;
    int** new_matrix = (int**)malloc(sizeof(int*)*4);
    for(i=0;i<4;i++){
        new_matrix[i] = (int*) malloc(sizeof(int)*4);
    }
    for(i=0;i<4;i++){
        for(j=0;j<4;j++){
            int first_bit = matrix[j%4][i]/128;
            int e_mul_x = (matrix[j%4][i]<<1)%256;
            if(first_bit)
                e_mul_x ^= 27;
            first_bit = e_mul_x/128;
            int e_mul_x2 = (e_mul_x<<1)%256;
            if(first_bit)
                e_mul_x2 ^= 27;
            first_bit = e_mul_x2/128;
            int e_mul_x3 = (e_mul_x2<<1)%256;
            if(first_bit)
                e_mul_x3 ^= 27;
            int e_mul = e_mul_x ^ e_mul_x2 ^ e_mul_x3;
            first_bit = matrix[(j+1)%4][i]/128;
            int b_mul_x = (matrix[(j+1)%4][i]<<1)%256;
            if(first_bit)
                b_mul_x ^= 27;
            first_bit = b_mul_x/128;
            int b_mul_x2 = (b_mul_x<<1)%256;
            if(first_bit)
                b_mul_x2 ^= 27;
            first_bit = b_mul_x2/128;
            int b_mul_x3 = (b_mul_x2<<1)%256;
            if(first_bit)
                b_mul_x3 ^= 27;
            int b_mul = matrix[(j+1)%4][i] ^ b_mul_x ^ b_mul_x3;
            first_bit = matrix[(j+2)%4][i]/128;
            int d_mul_x = (matrix[(j+2)%4][i]<<1)%256;
            if(first_bit)
                d_mul_x ^= 27;
            first_bit = d_mul_x/128;
            int d_mul_x2 = (d_mul_x<<1)%256;
            if(first_bit)
                d_mul_x2 ^= 27;
            first_bit = d_mul_x2/128;
            int d_mul_x3 = (d_mul_x2<<1)%256;
            if(first_bit)
                d_mul_x3 ^= 27;
            int d_mul = matrix[(j+2)%4][i] ^ d_mul_x2 ^ d_mul_x3;
            first_bit = matrix[(j+3)%4][i]/128;
            int mul_9_x = (matrix[(j+3)%4][i]<<1)%256;
            if(first_bit)
                mul_9_x ^= 27;
            first_bit = mul_9_x/128;
            int mul_9_x2 = (mul_9_x<<1)%256;
            if(first_bit)
                mul_9_x2 ^= 27;
            first_bit = mul_9_x2/128;
            int mul_9_x3 = (mul_9_x2<<1)%256;
            if(first_bit)
                mul_9_x3 ^= 27;
            int mul_9 = mul_9_x3 ^ matrix[(j+3)%4][i];
            new_matrix[j%4][i] = e_mul ^ b_mul ^ d_mul ^ mul_9;
        }
    }
    return new_matrix;
}

// shift row i of matrix left by i times - key generation algorithm
void shift_row(int** matrix)
{
    int i,j;
    for(i=0;i<4;i++){
        for(j=0;j<i;j++){
            right_shift(matrix[i]);
        }
    }
}

// right shift an array of 4 elements 
void right_shift(int* array)
{
    int temp = array[3];
    int i;
    for(i=2;i>=0;i--){
        array[i+1] = array[i];
    }
    array[0] = temp;
}

// left shift an array of 4 elements 
void left_shift(int* array)
{
    int temp = array[0];
    int i;
    for(i=0;i<3;i++){
        array[i] = array[i+1];
    }
    array[3] = temp;
}

// utility function to print a matrix of input rows and columns
void print_matrix(int** matrix, int rows,int cols)
{
    int i,j;
    for(i=0;i<rows;i++){
        for(j=0;j<cols;j++){
            printf("%x ", matrix[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}

// substitute each element of array with corresponding value from sbox
void sub_byte(int* array)
{
    int i;
    for(i=0;i<4;i++){
        int col = array[i]%16;
        int row = array[i]/16;
        array[i] = sbox[row][col];
    }
}