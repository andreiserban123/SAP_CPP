#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/applink.c>
#include <openssl/err.h>
#include <iostream>
using namespace std;

int main() {
	RSA* key_pair = NULL;

	unsigned char sha1_message_digest[] = { 0x17, 0x1E, 0x7E, 0xBC, 0x94, 0xF1, 0x38, 0x56,
		0x63, 0x68, 0x5F, 0xD8, 0x97, 0x9C, 0x26, 0x1B, 0xD6,
		0xE5, 0x56, 0x6C };

	FILE* pub_file = fopen("RSAPublicKey.pem", "r");
	if (pub_file == NULL) {
		cerr << "Error: Cannot open RSAPublicKey.pem file." << endl;
		return 1;
	}

	key_pair = PEM_read_RSAPublicKey(
		pub_file,
		NULL,
		NULL,
		NULL);

	if (key_pair == NULL) {
		cerr << "Error: Failed to read RSA public key from PEM file." << endl;
		cerr << "OpenSSL error: " << ERR_get_error() << endl;
		fclose(pub_file);
		return 1;
	}

	fclose(pub_file);

	// read the signature from file
	FILE* sig_file = fopen("RSASignature.sig", "rb");
	if (sig_file == NULL) {
		cerr << "Error: Cannot open RSASignature.sig file." << endl;
		RSA_free(key_pair);
		return 1;
	}

	int key_size = RSA_size(key_pair); // RSA key size in number of bytes
	unsigned char* signature = (unsigned char*)malloc(key_size);
	if (signature == NULL) {
		cerr << "Error: Memory allocation failed for signature." << endl;
		fclose(sig_file);
		RSA_free(key_pair);
		return 1;
	}
	memset(signature, 0x00, key_size);
	fread(signature, sizeof(unsigned char), key_size, sig_file);
	fclose(sig_file);

	// decrypt the signature
	unsigned char* decrypted_signature = (unsigned char*)malloc(key_size);
	if (decrypted_signature == NULL) {
		cerr << "Error: Memory allocation failed for decrypted signature." << endl;
		free(signature);
		RSA_free(key_pair);
		return 1;
	}
	memset(decrypted_signature, 0x00, key_size);
	int dec_size = RSA_public_decrypt(key_size, signature, decrypted_signature,
		key_pair, RSA_PKCS1_PADDING);

	if (dec_size < 0) {
		cerr << "Error: RSA decryption failed." << endl;
	}
	// compare the decrypted signature with the original message digest
	else if (dec_size != sizeof(sha1_message_digest) ||
		memcmp(sha1_message_digest, decrypted_signature, sizeof(sha1_message_digest)) != 0) {
		cout << "Signature verification failed." << endl;

	}
	else {
		cout << "Signature verification succeeded." << endl;
	
		cout << "Decrypted signature (message digest): ";
		for (unsigned char i = 0; i < dec_size; i++) {
			printf("%02X", decrypted_signature[i]);
		}
	}


	// cleanup
	free(signature);
	free(decrypted_signature);
	RSA_free(key_pair);
	
	return 0;
}