/*
 * ish2.c: an HTTP/2 support check tool via ALPN.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define TARGET_SIZE	1024

#ifdef __GNUC__
__attribute__ ((noreturn))
#endif
void exit_program(const char* target, const char* msg, int status, SSL_CTX* ctx, BIO* bio) {

	fprintf(stderr, "%s Error: %s\n", target, msg);

	BIO_free_all(bio);
	SSL_CTX_free(ctx);
	exit(status);
}

/* This function assumes `target` to have a size of `TARGET_SIZE` */
int parse_args(char target[], const char* host, const char* port) {
	char* aux;

	/* Remove protocol scheme if present */
	if ( (aux = strstr(host, "://")) != NULL ) {
		aux[2] = ' ';
		sscanf(host, "%*s %s", target);
	} else {
		strncpy(target, host, TARGET_SIZE);
	}

	target[TARGET_SIZE-1] = '\x0';

	/* Remove web path and port if present */
	if ( (aux = strchr(target, '/')) != NULL ) {
		*aux = '\x0';
	}
	if ( (aux = strchr(target, ':')) != NULL ) {
		*aux = '\x0';
	}

	/* Check for overflow and write final target string */
	if ( (strlen(target) + strlen(port) + 2) > TARGET_SIZE ) {
		return -1;
	}
	strcat(target, ":");
	strcat(target, port);

	return 0;
}

int main(int argc, char *argv[]) {
	char *port;
	char target[TARGET_SIZE], hostname[TARGET_SIZE];

	const unsigned char* alpn_proto;
	unsigned int alpn_length;

	const SSL_METHOD* method;
	SSL_CTX* ctx = NULL;
	BIO* bio = NULL;
	SSL* ssl = NULL;

	if (argc == 2) {
		port = "443";
	} else if (argc > 2) {
		port = argv[2];
	} else {
		fprintf(stderr, "Usage: %s host [port]\n", argv[0]);
		exit(EXIT_SUCCESS);
	}

	if (parse_args(target, argv[1], port) < 0) {
		exit_program(hostname, "Input target too long", EXIT_FAILURE, NULL, NULL);
	}

	/* Copy target without port into hostname */
	strncpy(hostname, target, TARGET_SIZE);
	{
		char* aux = strchr(hostname, ':');
		*aux = '\x0';
	}

	/* Set up SSL method and context */
	if ( (method = SSLv23_client_method()) == NULL ) {
		exit_program(hostname, ERR_error_string(ERR_get_error(), NULL), EXIT_FAILURE, NULL, NULL);
	}
	if ( (ctx = SSL_CTX_new(method)) == NULL) {
		exit_program(hostname, ERR_error_string(ERR_get_error(), NULL), EXIT_FAILURE, NULL, NULL);
	}

	/* Do not verify certificates */
	#ifdef NVERIFY
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	#endif

	/* Set ALPN */
	{
		unsigned char protos[12] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
		if ( (SSL_CTX_set_alpn_protos(ctx, protos, sizeof(protos))) != 0) {
			exit_program(hostname, ERR_error_string(ERR_get_error(), NULL), EXIT_FAILURE, ctx, NULL);
		}
	}

	/* Set up BIO */
	if ( (bio = BIO_new_ssl_connect(ctx)) == NULL) {
		exit_program(hostname, ERR_error_string(ERR_get_error(), NULL), EXIT_FAILURE, ctx, NULL);
	}
	if ( (BIO_set_conn_hostname(bio, target)) != 1 ) {
		exit_program(hostname, ERR_error_string(ERR_get_error(), NULL), EXIT_FAILURE, ctx, bio);
	}

	/* Set SNI */
	if (BIO_get_ssl(bio, &ssl) <= 0) {
		exit_program(hostname, ERR_error_string(ERR_get_error(), NULL), EXIT_FAILURE, ctx, bio);
	}
	if ( (SSL_set_tlsext_host_name(ssl, hostname)) != 1) {
		exit_program(hostname, ERR_error_string(ERR_get_error(), NULL), EXIT_FAILURE, ctx, bio);
	}

	/* Connect */
	if ( BIO_do_connect(bio) != 1 || BIO_do_handshake(bio) != 1 ) {
		exit_program(hostname, ERR_error_string(ERR_get_error(), NULL), EXIT_FAILURE, ctx, bio);
	}

	/* Print result */
	printf("%s ", hostname);
	SSL_get0_alpn_selected(ssl, &alpn_proto, &alpn_length);
	if (alpn_proto != NULL) {
		printf("%.*s\n", alpn_length, alpn_proto);
	} else {
		printf("http/1.1\n");
	}

	SSL_CTX_free(ctx);
	BIO_free_all(bio);

	return 0;
}
