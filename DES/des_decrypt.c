/*
	Name - Sai Saketh Aluru
	Roll No. - 16CS30030
*/
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

//function declarations
void convert_char_to_ascii(char* ciphertext, char* ciphertext_bits);
void convert_ascii_to_char(char* plaintext_bits, char* plaintext);
char* decrypt(char* block, char* key);
char* permute(char* block, int* sequence,int size);
char* round_function(char* block,char* key);
char* xor(char* block_1, char* block_2,int size);
char* key_lcs(char* key,int amount);
char* key_rcs(char* key, int amount);

// Permutation tables
int IP[64] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
};

int IPinverse[64] = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
};

// Key scheduling tables
int PC1[56] = {
   57, 49, 41, 33, 25, 17,  9,
    1, 58, 50, 42, 34, 26, 18,
   10,  2, 59, 51, 43, 35, 27,
   19, 11,  3, 60, 52, 44, 36,
   63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
   14,  6, 61, 53, 45, 37, 29,
   21, 13,  5, 28, 20, 12,  4
};

int PC2[48] = {
   14, 17, 11, 24,  1,  5,
    3, 28, 15,  6, 21, 10,
   23, 19, 12,  4, 26,  8,
   16,  7, 27, 20, 13,  2,
   41, 52, 31, 37, 47, 55,
   30, 40, 51, 45, 33, 48,
   44, 49, 39, 56, 34, 53,
   46, 42, 50, 36, 29, 32
};

int Rotations[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

// Round tables

int Expansion[48] = {
    32,  1,  2,  3,  4,  5,  4,  5,
     6,  7,  8,  9,  8,  9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27,
    28, 29, 28, 29, 30, 31, 32,  1
}; 
// DES Sboxes
int Sbox[8][4][16] = {
   {
   {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
   { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
   { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
   {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13},
   },
 
   {
   {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
   { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
   { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
   {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9},
   },
 
   {
   {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
   {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
   {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
   { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12},
   },
 
   {
   { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
   {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
   {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
   { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14},
   },
 
   {
   { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
   {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
   { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
   {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3},
   },
 
   {
   {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
   {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
   { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
   { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13},
   },
 
   {
   { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
   {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
   { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
   { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12},
   },
 
   {
   {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
   { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
   { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
   { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11},
   },
};

int Pbox[32] = {
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25
};

int main()
{
	char ciphertext[100],plaintext[100],key[10];
	printf("Enter ciphertext(max 100 characters) to decrypt: ");
	// scanf("%s",ciphertext);
	char ciphertext_bits[1000];
	scanf("%s",ciphertext_bits);
	printf("Enter key(of 8 characters) for decryption: ");
	scanf("%s",key);
	char* KEY = (char*) malloc(sizeof(char)*65);
	// convert_char_to_ascii(ciphertext,ciphertext_bits);
	convert_char_to_ascii(key,KEY);
	char plaintext_bits[1000];
	int i;
	char* block = (char*)malloc(sizeof(char)*65);
	for(i=0;i<64;i++){
		block[i]='0';
	}
	block[64]='\0';
	int j;
	for(i=0;i<strlen(ciphertext_bits);i+=64){
		for(j=0;j<64;j++){
			if(i+j<strlen(ciphertext_bits)){
				block[j] = ciphertext_bits[i+j];
			}
		}
		block[64] = '\0';
		block = decrypt(block,KEY);
		for(j=0;j<64;j++){
			plaintext_bits[i+j] = block[j];
		}
	}
	plaintext_bits[i] = '\0';
	printf("plaintext_bits = %s\n",plaintext_bits);
	convert_ascii_to_char(plaintext_bits,plaintext);
	printf("plaintext = %s\n",plaintext);
	return 0;
}
// function to convert an array of char each to 8 bit binary ascii codes
void convert_char_to_ascii(char* ciphertext, char* ciphertext_bits)
{
	int i,len=strlen(ciphertext),j=0,k;
	for(i=0;i<len;i++){
		int ascii = (int)ciphertext[i];
		int decimal = 0;
		for(k=0;k<8;k++){
			decimal*=10;
			decimal+= ascii%2;
			ascii /= 2;
		}
		for(k=0;k<8;k++){
			ciphertext_bits[j++] = (char)((decimal%10)+'0');
			decimal/=10;
		}
	}
	ciphertext_bits[j] = '\0';
}
// function to convert 8-bit binary ascii codes to chars
void convert_ascii_to_char(char* plaintext_bits, char* plaintext)
{
	int i,len=strlen(plaintext_bits),j=0,k=0;
	for(i=0;i<len;i+=8){
		int ascii = 0;
		for(j=0;j<8;j++){
			ascii += (int)(plaintext_bits[i+j]-'0')*pow(2,(7-j));
		}
		plaintext[k++] = (char)ascii;
	}
	plaintext[k] = '\0';
}
// decryption function
char* decrypt(char* block, char* key)
{
	block = permute(block,IP,64);
	key = permute(key,PC1,56);
	int rounds = 16,i;
	char* round_key = (char*)malloc(sizeof(char)*48);
	key = key_lcs(key,28);
	for(i=0;i<rounds;i++){
		round_key = permute(key,PC2,48);
		block = round_function(block,round_key);
		key = key_rcs(key,Rotations[15-i]);
	}
	for(i=0;i<32;i++){
		char temp = block[i];
		block[i] = block[i+32];
		block[i+32] = temp;
	}
	block = permute(block,IPinverse,64);
	block[65]='\0';
	return block;
}
/* 
	function to take a block and sequence of given size 
	and permute it according to the sequence
*/

char* permute(char* block, int* sequence,int size)
{
	char* output = (char*)malloc(sizeof(char)*size+1);
	int i;
	for(i=0;i<size;i++){
		output[i] = block[sequence[i]-1];
	}
	output[size] = '\0';
	return output;
}

char* round_function(char* block,char* key)
{
	char left_half[33],right_half[33];
	int i;
	for(i=0;i<32;i++){
		left_half[i] = block[i];
		right_half[i] = block[i+32];
	}
	left_half[i] = '\0';
	right_half[i] = '\0';
	char* expanded_right_half = (char*)malloc(49*sizeof(char));
	expanded_right_half = permute(right_half,Expansion,48);
	expanded_right_half[48] = '\0';
	expanded_right_half = xor(expanded_right_half,key,48);
	char* s_box_output = (char*)malloc(32*sizeof(char));
	int j=0;
	for(i=0;i<8;i++){
		int row = (int)(expanded_right_half[6*i]-'0')*2+(int)(expanded_right_half[6*i+5]-'0');
		int col = (int)(expanded_right_half[6*i+1]-'0')*8+ (int)(expanded_right_half[6*i+2]-'0')*4
					+ (int)(expanded_right_half[6*i+3]-'0')*2+ (int)(expanded_right_half[6*i+4]-'0');
		int val = Sbox[i][row][col];
		s_box_output[j++] = (char)(val/8 + '0');
		val%=8;
		s_box_output[j++] = (char)(val/4 + '0');
		val%=4;
		s_box_output[j++] = (char)(val/2 + '0');
		val%=2;
		s_box_output[j++] = (char)(val + '0');
	}
	s_box_output = permute(s_box_output,Pbox,32);
	char* new_right_half = (char*)malloc(33*sizeof(char));
	new_right_half = xor(s_box_output,left_half,32);
	char* output = (char*)malloc(sizeof(char)*65);
	for(i=0;i<32;i++){
		output[i] = right_half[i];
		output[i+32] = new_right_half[i];
	}
	output[64] = '\0';
	return output;
}
/*
	function that performs bitwise xor over 
	two character arrays containing binary numbers
	of given size
*/
char* xor(char* block_1, char* block_2,int size)
{
	int i=0;
	char* output = (char*)malloc(size*sizeof(char));
	for(i=0;i<size;i++){
		if(block_1[i]==block_2[i])
			output[i] = '0';
		else output[i] = '1';
	}
	output[i]='\0';
	return output;
}

/*
	function that takes a key array and integer amount as input
	and circular shifts the key to left by the given amount
*/
char* key_lcs(char* key,int amount)
{
	char* output = (char*)malloc(sizeof(char)*57);
	int i;
	for(i=0;i<28;i++){
		output[i] = key[(i+amount)%28];
	}  
	for(i=28;i<56;i++){
		output[i] = key[((i+amount)%28)+28];
	}
	output[56]='\0';
	return output;
}

/*
	function that takes a key array and integer amount as input
	and circular shifts the key to right by the given amount
*/
char* key_rcs(char* key, int amount)
{
	char* output = (char*)malloc(sizeof(char)*57);
	int i;
	for(i=0;i<28;i++){
		output[i] = key[(i-amount+28)%28];
	}
	for(i=28;i<56;i++){
		output[i] = key[((i-amount+28)%28)+28];
	}
	output[56]='\0';
	return output;
}