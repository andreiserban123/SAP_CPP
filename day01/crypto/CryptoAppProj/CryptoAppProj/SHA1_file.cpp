#include <openssl/sha.h>
#include <stdio.h>

// Add additional include Directories: path to the <openssl_bundle>/include

#define MESSAGE_BLOCK_LENGHT 12

int main()
{
	unsigned char message[MESSAGE_BLOCK_LENGHT];
	FILE* file = NULL;
	file = fopen("input.bin", "rb");


	// define context
	SHA_CTX shaContext;


	// intialize the MD context structure

	int result = SHA1_Init(&shaContext);
	if (result != 1) {
		printf("SHA1_Init failed\n");
		return 1;
	}

	// update the MD context structure
	// using a loop to simulate multiple blocks

	
	unsigned short int bytes_read = fread(message, sizeof(unsigned char), MESSAGE_BLOCK_LENGHT, file);
	while (bytes_read > 0)
	{
		result = SHA1_Update(&shaContext, message, bytes_read);
		if (result != 1) {
			printf("SHA1_Update failed\n");
			return 1;
		}
		bytes_read = fread(message, sizeof(unsigned char), MESSAGE_BLOCK_LENGHT, file);
	}

	fclose(file);
	// get the final result of MD

	unsigned char hash[SHA_DIGEST_LENGTH];
	result = SHA1_Final(hash, &shaContext);
	if (result != 1) {
		printf("SHA1_Final failed\n");
		return 1;
	}
	printf("SHA1 Digest: ");
	for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
		printf("%02X ", hash[i]);
	}

	return 0;
}