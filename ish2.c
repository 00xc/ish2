
#include <stdio.h>

#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <string.h>

int main(int argc, char *argv[]){

	char *host, *port, *target; /* Target params */
	SSL_CTX *ctx = NULL;	/* SSL context */
	BIO *web = NULL; /* BIO to send data (prob. not necessary) */
	SSL *ssl = NULL;	/* SSL connection object */
	long res = 1;	/* Variable para check status */
	int i = 0;

	/* Read inputs */
	if(argc > 1){
		host = argv[1];
		if (argc > 2){
			port = argv[2];
		} else {
			port = "443";
		}
	} else {
		printf("Usage: %s <IP> [<port=443>]\n", argv[0]);
		exit(0);
	}

	/* Parse inputs */
	char *p = strstr(host, "://");
	if(p){
		host = p+3;
	}
	target = malloc(strlen(host)+strlen(port)+1);
	sprintf(target, "%s:%s", host, port);

	/* Init SSL library */
	(void) SSL_library_init();
	SSL_load_error_strings();
	OPENSSL_config(NULL);

	/* Set up SSL method */
	const SSL_METHOD *method = TLSv1_2_method();
	if(method == NULL){
		printf("Error setting up method\n");
		exit(1);
	}

	/* Set up SSL context */
	ctx = SSL_CTX_new(method);
	if(ctx == NULL){
		printf("Error setting up context\n");
		exit(1);
	}

	/* Don't verify peer */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	/* Flags */
	const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_COMPRESSION;
	SSL_CTX_set_options(ctx, flags);

	/* ALPN */
	unsigned char protos[] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
	unsigned int protos_len = sizeof(protos);
	res = SSL_CTX_set_alpn_protos(ctx, protos, protos_len);
	if(res != 0){
		printf("Error setting ALPN protocols\n");
		exit(1);
	}

	/* Setup BIO web */
	web = BIO_new_ssl_connect(ctx);
	if(web == NULL){
		printf("Error setting up context\n");
		exit(1);
	}
	res = BIO_set_conn_hostname(web, target);
	if(res != 1){
		printf("Error setting hostname");
		exit(1);
	}
	BIO_get_ssl(web, &ssl);
	if(ssl == NULL){
		printf("Error setting up SSL object.\n");
		exit(1);
	}

	/* Cipher suites */
	//const char* const ciphers = "HIGH:ECDHE";
	const char* const ciphers = "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5;";
	res = SSL_set_cipher_list(ssl, ciphers);
	if(res != 1){
		printf("Error setting up cipher suites\n");
		exit(1);
	}

	/* Set hostname */
	res = SSL_set_tlsext_host_name(ssl, host);
	if(res != 1){
		printf("Error setting up hostname");
		exit(1);
	}

	/* Connect */
	res = BIO_do_connect(web);
	if(res != 1){
		printf("Error connecting\n");
		exit(1);
	}
	res = BIO_do_handshake(web);
	if(res != 1){
		printf("Error performing handshake");
		exit(1);
	}

	/* Read ALPN */
	printf("Protocol: ");
	char *alpn_proto = ssl->s3->alpn_selected;
	unsigned int alpn_length = (unsigned int) ssl->s3->alpn_selected_len;
	if(alpn_proto != NULL){
		printf("%.*s\n", alpn_length, alpn_proto);
	} else {
		printf("http/1.1\n");
	}

	/* Free variables */
	if(web != NULL){
		BIO_free_all(web);
	}
	if(ctx != NULL){
		SSL_CTX_free(ctx);
	}
	free(target);
}