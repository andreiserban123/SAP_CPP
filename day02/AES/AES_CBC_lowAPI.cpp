#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

int main() {

	unsigned char plaintext[] = "This is a longer text that needs to be encrypted!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";

	unsigned char key_256[] = {
		0xff,0xab,0xff,0xce,0x1f,0x0d,0x88,0xe9,
		0xab,0xff,0xec,0xff,0xf1,0xc1,0x99,0xd8,
		0xff,0xab,0xff,0xce,0x1f,0x0d,0x88,0xe9,
		0xab,0xff,0xec,0xff,0xf1,0xc1,0x99,0xd8,
	};

	
	unsigned char IV_backup[AES_BLOCK_SIZE];
	unsigned char IV[AES_BLOCK_SIZE] = {
		0xab,0xbb,0xcb,0xab,0xab,0xab,0xab,0xab,
		0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab
	};

	memcpy(IV_backup, IV, AES_BLOCK_SIZE);
	AES_KEY aes_key_256;

	AES_set_encrypt_key(key_256, (const int)sizeof(key_256) * 8, &aes_key_256);

	unsigned short int no_blocks_ciphertext = (sizeof(plaintext) / AES_BLOCK_SIZE);

	if (sizeof(plaintext) % AES_BLOCK_SIZE != 0)
	{
		no_blocks_ciphertext += 1;
	}

	unsigned char* ciphertext = (unsigned char*)malloc(no_blocks_ciphertext * AES_BLOCK_SIZE);

	if (ciphertext == NULL)
	{
		printf("Memory allocation failed\n");
		free(ciphertext);
		return -1;
	}
	memset(ciphertext, 0x00, no_blocks_ciphertext * AES_BLOCK_SIZE);

	// after exection the AES_cbc_encrypt function, the IV content is changed.
	// encrypt all plaintext content in one shot operation
	AES_cbc_encrypt(plaintext, ciphertext, sizeof(plaintext), &aes_key_256, IV, AES_ENCRYPT);

	printf("Ciphertext:\n");
	for (size_t i = 0; i < no_blocks_ciphertext * AES_BLOCK_SIZE; i++)
	{
		printf("%02X", ciphertext[i]);
	}

	// decrypt ciphertext

	AES_KEY decryptkey;
	AES_set_decrypt_key(key_256, (const int)sizeof(key_256) * 8, &decryptkey);
	

	unsigned char* restore =(unsigned char*) malloc(sizeof(plaintext));
	if (restore == NULL) {
		printf("Memory allocation failed\n");
		free(restore);
		return -1;
	}

	unsigned char* decrypted_buffer = (unsigned char*)malloc(no_blocks_ciphertext * AES_BLOCK_SIZE);
	if (decrypted_buffer == NULL) {
		printf("Memory allocation failed\n");
		free(decrypted_buffer);
		return -1;
	}
	
	AES_set_decrypt_key(key_256, (const int)sizeof(key_256) * 8, &aes_key_256);
	

	AES_cbc_encrypt(ciphertext, decrypted_buffer, no_blocks_ciphertext * AES_BLOCK_SIZE, &decryptkey, IV_backup, AES_DECRYPT);

	memcpy(restore, decrypted_buffer, sizeof(plaintext));

	if (memcmp(plaintext, restore, sizeof(plaintext)) == 0)
	{
		printf("\n\nDecryption successful and plaintext restored correctly.");
	}
	else
	{
		printf("\n\nDecryption failed and plaintext not restored correctly.");
	}
	printf("\n\nRestored Plaintext:\n%s\n", restore);
	free(restore);
	free(decrypted_buffer);
	free(ciphertext);
	return 0;
}