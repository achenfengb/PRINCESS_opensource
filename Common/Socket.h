#ifndef SOCKET_H
#define SOCKET_H

#include "openssl/ssl.h"

#define MAXPAIRNUM 100

class Socket
{
  public:
    Socket(): SS(-1), IsBlocking(true), IsNoDelay(false) { curID = 0; SSLenable = 0; }
    Socket(const char *Server,unsigned short Port,bool IsUDP=false);
    ~Socket();

    bool IsConnected(void) { return(SS>=0); }

    bool Connect(const char *Server,unsigned short Port,bool IsUDP=false);
	int Accept();
    void Close(int SS);
    void Close();

    bool SetBlocking(bool Switch);
    bool SetNoDelay(bool Switch);
    bool SetRecvBuffer(int BufLeng);
    int  GetRecvBuffer();

    int Send(int SS, const void *Buf,int Size);
    int Recv(int SS, void *Buf,int Size);

    int Send(const void *Buf,int Size);
    int Recv(void *Buf,int Size);

	int SendInitInfo(int SS, const void *Buf,int Size);
    int RecvInitInfo(int SS, void *Buf,int Size);

	int GetSockfd();

	SSL *findSSLCtx(int socket_fd);
	int setSSLenable(bool enable);
	int setSSLpair(SSL *ssl, int socket_fd);

  private:
    int SS;
	int LSocket;
	int PPort;
    bool IsBlocking;
    bool IsNoDelay;

	bool SSLenable;
	SSL *ssl_client_list[MAXPAIRNUM];
	int client_socket_fd_list[MAXPAIRNUM];
	int curID;
};

#endif /* SOCKET_H */
