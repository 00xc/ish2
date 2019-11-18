
#include <stdio.h>
#include <errno.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <string.h>

void exit_program(char *target, int status, char *msg){

	char* prhost = strtok(target, ":");

	printf("%s %s\n", prhost, msg);
	free(target);
	exit(status);
}

int main(int argc, char *argv[]){

	char *host, *port, *target;		/* Target params */
	SSL_CTX *ctx = NULL;			/* SSL context */
	SSL *ssl = NULL;				/* SSL connection struct */
	BIO *web = NULL;				/* BIO to do handshake with */

	/* Read inputs */
	if (argc > 1){
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

	/* Remove protocol scheme */
	char parsed_host[strlen(host)];
	char *p = strstr(host, "://");
	if(p){
		p[0] = ' ';
		p[2] = ' ';
		sscanf(host, "%*s %*s %s", parsed_host);
	} else {
		strcpy(parsed_host, host);
	}

	/* Remove web path and port */
	p = strchr(parsed_host, '/');
	if (p){
		*p = '\x0';
	}
	p = strchr(parsed_host, ':');
	if (p){
		*p = '\x0';
	}

	/* Allocate target string */
	if ( (target = malloc(strlen(parsed_host)+strlen(port)+2)) == NULL ){
		perror("malloc");
		exit(-1);
	}
	sprintf(target, "%s:%s", parsed_host, port);

	/* Init SSL library */
	(void) SSL_library_init();
	SSL_load_error_strings();
	OPENSSL_config(NULL);

	/* Set up SSL method */
	const SSL_METHOD *method = SSLv23_client_method();
	if(method == NULL){
		exit_program(target, 1, "Error: TLS method");
	}

	/* Set up SSL context */
	if( (ctx = SSL_CTX_new(method)) == NULL){
		exit_program(target, 1, "Error: TLS context");
	}

	/* Don't verify peer*/
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	/* Set ALPN */
	unsigned char protos[] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
	if( (SSL_CTX_set_alpn_protos(ctx, protos, sizeof(protos))) != 0){
		exit_program(target, 1, "Error: cannot set ALPN");
	}

	/* Setup BIO web */
	web = BIO_new_ssl_connect(ctx);
	if(web == NULL){
		exit_program(target, 1, "Error: cannot set BIO");
	}
	if( (BIO_set_conn_hostname(web, target)) != 1){
		exit_program(target, 1, "Error: BIO_set_conn_hostname()");
	}
	BIO_get_ssl(web, &ssl);
	if(ssl == NULL){
		exit_program(target, 1, "Error: cannot set TLS struct");
	}

	/* Set hostname */
	if( (SSL_set_tlsext_host_name(ssl, host)) != 1){
		exit_program(target, 1, "Error: SSL_set_tlsext_host_name()");
	}

	/* Connect */
	if( (BIO_do_connect(web)) != 1){
		exit_program(target, 1, "Error: cannot connect/host does not support TLS");
	}
	if( (BIO_do_handshake(web)) != 1){
		exit_program(target, 1, "Error: BIO_do_handshake()");
	}

	char* prhost = strtok(target, ":");
	printf("%s ", prhost);

	/* Read ALPN */
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