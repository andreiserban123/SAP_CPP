#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/applink.c>
#include <openssl/err.h>
#include <iostream>
using namespace std;

int main(int argc,char* argv[]) {
	RSA* key_pair = NULL;

	if (argc == 4)
	{
		// get the public key (from the PEM file)
		FILE* pub_file = fopen(argv[1], "r");
		if (pub_file == NULL) {
			cerr << "Error: Cannot open public key file." << endl;
			return 1;
		}

		key_pair = PEM_read_RSAPublicKey(
			pub_file,
			NULL,
			NULL,
			NULL);
		fclose(pub_file);

		if (key_pair == NULL) {
			cerr << "Error: Failed to read RSA public key." << endl;
			cerr << "OpenSSL error: " << ERR_get_error() << endl;
			return 1;
		}

		int key_size = RSA_size(key_pair);

		// read the plain text file
		FILE* plain_file = fopen(argv[2], "rb");
		if (plain_file == NULL) {
			cerr << "Error: Cannot open plaintext file." << endl;
			RSA_free(key_pair);
			return 1;
		}

		fseek(plain_file, 0, SEEK_END);
		long plain_size = ftell(plain_file);
		fseek(plain_file, 0, SEEK_SET);

		if (plain_size <= 0) {
			cerr << "Error: Plaintext file is empty." << endl;
			fclose(plain_file);
			RSA_free(key_pair);
			return 1;
		}

		unsigned int max_block_size = key_size - 11;
		unsigned int no_blocks = (plain_size + max_block_size - 1) / max_block_size;

		unsigned char* input = (unsigned char*)malloc(key_size);
		unsigned char* output = (unsigned char*)malloc(key_size);

		if (input == NULL || output == NULL) {
			cerr << "Error: Memory allocation failed." << endl;
			free(input);
			free(output);
			fclose(plain_file);
			RSA_free(key_pair);
			return 1;
		}

		FILE* cipher_file = fopen(argv[3], "wb+");
		if (cipher_file == NULL) {
			cerr << "Error: Cannot create cipher file." << endl;
			free(input);
			free(output);
			fclose(plain_file);
			RSA_free(key_pair);
			return 1;
		}

		// Process all blocks
		for (unsigned int i = 0; i < no_blocks; i++) {
			memset(input, 0x00, key_size);
			memset(output, 0x00, key_size);
			
			unsigned int read_bytes = fread(input, sizeof(unsigned char), max_block_size, plain_file);
			
			int enc_size = RSA_public_encrypt(read_bytes, input, output,
				key_pair, RSA_PKCS1_PADDING);

			if (enc_size != key_size) {
				cerr << "Error during encryption." << endl;
				free(input);
				free(output);
				fclose(plain_file);
				fclose(cipher_file);
				RSA_free(key_pair);
				return 1;
			}

			size_t write_bytes = fwrite(output, sizeof(unsigned char), enc_size, cipher_file);
			if (write_bytes != enc_size) {
				cerr << "Error during writing ciphertext." << endl;
				free(input);
				free(output);
				fclose(plain_file);
				fclose(cipher_file);
				RSA_free(key_pair);
				return 1;
			}
		}

		RSA_free(key_pair);
		free(input);
		free(output);
		fclose(plain_file);
		fclose(cipher_file);
		cout << "Encryption completed successfully." << endl;


	}
	else {
		cout << "Usage: app.exe RSAPublicKey.pem plain.txt cipher.file" << endl;
		return 1;
	}

	return 0;
}