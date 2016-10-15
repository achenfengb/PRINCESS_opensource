#include "openssl\ssl.h"
#include "openssl\err.h"
#include "openssl\crypto.h"
#include "openssl\x509.h"
#include "openssl\pem.h"
#include <ws2tcpip.h>
#include <Windows.h>
#include <Winsock2.h>
#include "openssl\bio.h"
#include "openssl\err.h"
#include "openssl\x509_vfy.h"


#define VERBOSE true // if show the communication info

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

//get SSL_CTX.
SSL_CTX * initilizeSSL();

//establish SSL
SSL* establishSSL(int socketfd, SSL_CTX* ctx);

void disconnectSSL(SSL* ssl);

//free ctx
void freeCTX(SSL_CTX * ctx);

int inet_aton(const char *cp, struct in_addr *ap);
void verifyCertificate(SSL * ssl);