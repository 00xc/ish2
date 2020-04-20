/*
 * ish2.c: a HTTP/2 support check tool via ALPN.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>

#include <openssl/opensslv.h>

void exit_program(char* target, int status, char* msg, SSL_CTX* ctx, BIO* bio) {

	char* prhost = strtok(target, ":");
	printf("%s %s\n", prhost, msg);

	SSL_CTX_free(ctx);
	BIO_free_all(bio);
	free(target);
	exit(status);
}

int main(int argc, char *argv[]) {

	char *host, *port, *target;		/* Target params */
	SSL_CTX *ctx = NULL;			/* SSL context */
	SSL *ssl = NULL;			/* SSL connection struct */
	BIO *web = NULL;			/* BIO to do handshake with */
	const SSL_METHOD* method;		/* TLS method */

	const unsigned char* alpn_proto;	/* Pointer to buffer with ALPN information */
	unsigned int alpn_length;		/* Length of ALPN buffer */

	printf("%s\n", OPENSSL_VERSION_TEXT );

	/* Read inputs */
	if (argc > 1) {
		host = argv[1];
		if (argc > 2)
			port = argv[2];
		else
			port = "443";
	} else {
		printf("Usage: %s <IP> [<port=443>]\n", argv[0]);
		exit(0);
	}

	/* Remove protocol scheme */
	char parsed_host[strlen(host)];
	char *p = strstr(host, "://");
	if (p) {
		p[0] = ' ';
		p[2] = ' ';
		sscanf(host, "%*s %*s %s", parsed_host);
	} else {
		strcpy(parsed_host, host);
	}

	/* Remove web path and port */
	p = strchr(parsed_host, '/');
	if (p) {
		*p = '\x0';
	}
	p = strchr(parsed_host, ':');
	if (p) {
		*p = '\x0';
	}

	/* Allocate target string */
	if ( (target = malloc(strlen(parsed_host)+strlen(port)+2)) == NULL ) {
		perror("malloc");
		exit(-1);
	}
	sprintf(target, "%s:%s", parsed_host, port);

	/* Init SSL library */
	SSL_library_init();
	SSL_load_error_strings();

	/* Set up SSL method */
	if ( (method = SSLv23_client_method()) == NULL )
		exit_program(target, 1, "Error: TLS method", NULL, NULL);

	/* Set up SSL context */
	if ( (ctx = SSL_CTX_new(method)) == NULL)
		exit_program(target, 1, "Error: TLS context", NULL, NULL);

	/* Don't verify peer*/
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	/* Set ALPN */
	unsigned char protos[] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
	if ( (SSL_CTX_set_alpn_protos(ctx, protos, sizeof(protos))) != 0)
		exit_program(target, 1, "Error: cannot set ALPN", ctx, NULL);

	/* Setup BIO web */
	if ( (web = BIO_new_ssl_connect(ctx)) == NULL)
		exit_program(target, 1, "Error: cannot set BIO", ctx, NULL);

	if ( (BIO_set_conn_hostname(web, target)) != 1 )
		exit_program(target, 1, "Error: BIO_set_conn_hostname()", ctx, web);

	BIO_get_ssl(web, &ssl);
	if (ssl == NULL)
		exit_program(target, 1, "Error: cannot set TLS struct", ctx, web);

	/* Set hostname */
	if ( (SSL_set_tlsext_host_name(ssl, host)) != 1)
		exit_program(target, 1, "Error: SSL_set_tlsext_host_name()", ctx, web);

	/* Connect */
	if ( (BIO_do_connect(web)) != 1)
		exit_program(target, 1, "Error: cannot connect/host does not support TLS", ctx, web);
	if ( (BIO_do_handshake(web)) != 1)
		exit_program(target, 1, "Error: BIO_do_handshake()", ctx, web);

	char* prhost = strtok(target, ":");
	printf("%s ", prhost);

	/* Get ALPN and print */
	SSL_get0_alpn_selected(ssl, &alpn_proto, &alpn_length);
	if (alpn_proto != NULL) {
		printf("%.*s\n", alpn_length, alpn_proto);
	} else {
		printf("http/1.1\n");
	}

	/* Free variables */
	BIO_free_all(web);
	SSL_CTX_free(ctx);
	free(target);

	return(0);
}