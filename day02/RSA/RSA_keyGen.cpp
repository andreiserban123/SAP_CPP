#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/applink.c>
#include <iostream>

int main() {
	RSA* key_pair;

	key_pair =  RSA_generate_key(1024, 17, NULL, NULL);
	
	FILE* priv_file = fopen("RSAPrivateKey.pem", "wb+");
	PEM_write_RSAPrivateKey(priv_file, key_pair, NULL, NULL, 0, NULL, NULL);


	FILE* pub_file = fopen("RSAPublicKey.pem", "wb+");
	PEM_write_RSAPublicKey(pub_file, key_pair);


	RSA_free(key_pair);
	fclose(priv_file);
	fclose(pub_file);
	
	return 0;
}