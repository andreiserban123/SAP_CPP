#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

int main() {

	unsigned char plaintext[] = "This is a longer text that needs to be encrypted!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";

	unsigned char key_128[16] = {
		0xff,0xab,0xff,0xce,0x1f,0x0d,0x88,0xe9,
		0xab,0xff,0xec,0xff,0xf1,0xc1,0x99,0xd8,
	};
	// AES key + prepare the key for usage
	AES_KEY aes_key_128;
	AES_KEY aes_key_decrypt;
	AES_set_encrypt_key(key_128, sizeof(key_128) * 8, &aes_key_128);
	AES_set_decrypt_key(key_128, sizeof(key_128) * 8, &aes_key_decrypt);

	// encrypt the plaintext at AES block level
	unsigned short int no_of_blocks = (sizeof(plaintext) / AES_BLOCK_SIZE);
	if ((sizeof(plaintext) % AES_BLOCK_SIZE) != 0) {
		no_of_blocks++; // there is a partial block in plaintext
	}


	// save the output block in a buffer


	unsigned char* ciphertext = (unsigned char*) malloc(no_of_blocks * AES_BLOCK_SIZE);
	if (ciphertext == NULL) {
		printf("Error: Memory allocation failed\n");
		free(ciphertext);
		return 1;
	}

	for(unsigned short int i = 0; i < no_of_blocks - 1; i++) {
		AES_encrypt(
			plaintext + (i * AES_BLOCK_SIZE),
			ciphertext + (i* AES_BLOCK_SIZE),
			&aes_key_128
			);
	}

	

	if ((sizeof(plaintext) % AES_BLOCK_SIZE) != 0) {


		// the is a last partial block in plaintext
		unsigned char last_partial_block[AES_BLOCK_SIZE];
		unsigned char no_bytes = sizeof(plaintext) % AES_BLOCK_SIZE;
		memset(last_partial_block, 0x00, AES_BLOCK_SIZE);
		memcpy(last_partial_block, plaintext + (sizeof(plaintext) - no_bytes), no_bytes);
		AES_encrypt(
			last_partial_block,
			ciphertext + ((no_of_blocks - 1) * AES_BLOCK_SIZE),
			&aes_key_128
		);
	
	}
	else {
		// the last block in plaintext is full filled in by content 
		AES_encrypt(
			plaintext + (sizeof(plaintext) - AES_BLOCK_SIZE),
			ciphertext + (sizeof(plaintext) - AES_BLOCK_SIZE),
			&aes_key_128
		);	
	}

	printf("Ciphertext:\n");
	for (int i = 0; i < no_of_blocks * AES_BLOCK_SIZE; i++) {
		printf("%02x ", ciphertext[i]);
	}

	// decrypt the ciphertext at AES block level
	unsigned char* decryptedtext = (unsigned char*)malloc(sizeof(plaintext));

	int no_block_ciphertext = no_of_blocks * AES_BLOCK_SIZE;

	if(decryptedtext == NULL) {
		printf("Error: Memory allocation failed\n");
		free(ciphertext);
		return 1;
	}
	memset(decryptedtext, 0x00, sizeof(plaintext));

	for (unsigned short int i = 0; i < no_of_blocks - 1; i++) {
		AES_decrypt(
			ciphertext + (i * AES_BLOCK_SIZE),
			decryptedtext + (i * AES_BLOCK_SIZE),
			&aes_key_decrypt
		);
	}

	if ((sizeof(plaintext) % AES_BLOCK_SIZE) != 0) {
		unsigned char last_partial_block[AES_BLOCK_SIZE];
		unsigned char no_bytes = sizeof(plaintext) % AES_BLOCK_SIZE;
		memset(last_partial_block, 0x00, AES_BLOCK_SIZE);

		AES_decrypt(
			ciphertext + ((no_of_blocks - 1) * AES_BLOCK_SIZE),
			last_partial_block,
			&aes_key_decrypt
		);
		memcpy(decryptedtext + ((no_of_blocks - 1) * AES_BLOCK_SIZE), last_partial_block, no_bytes);
	}
	else {
		AES_decrypt(
			ciphertext + ((no_of_blocks - 1) * AES_BLOCK_SIZE),
			decryptedtext + ((no_of_blocks - 1) * AES_BLOCK_SIZE),
			&aes_key_decrypt
		);
	}

	if (memcmp(plaintext, decryptedtext, sizeof(plaintext)) != 0) {
		printf("\nDecryption failed: Decrypted text does not match the original plaintext.\n");
	}
	else {
		printf("\nDecryption successful: Decrypted text matches the original plaintext.\n");
	}
	printf("\n\nDecryptedtext:\n%s\n", decryptedtext);
	free(decryptedtext);
	free(ciphertext);

	return 0;
}