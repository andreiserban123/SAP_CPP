#include <openssl/sha.h>
#include <stdio.h>

// Add additional include Directories: path to the <openssl_bundle>/include

#define MESSAGE_BLOCK_LENGHT 12

int main() 
{

	unsigned char message[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
								0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
								0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	
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
	
	unsigned short int remaining_length = sizeof(message);
	while(remaining_length > 0)
	{
		unsigned short int current_block_length = (remaining_length > MESSAGE_BLOCK_LENGHT) ? MESSAGE_BLOCK_LENGHT : remaining_length;
		result = SHA1_Update(&shaContext, message + (sizeof(message) - remaining_length), current_block_length);
		if (result != 1) {
			printf("SHA1_Update failed\n");
			return 1;
		}
		remaining_length -= current_block_length;
	} 
	
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