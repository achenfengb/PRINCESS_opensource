#include <iostream>
#include <tchar.h>
#pragma once

#include <chrono>
#include "sgx_urts.h" 
#include "TDT_enclave_u.h"
#include "Socket.h"
#include "AnalysisMethod.h"

using namespace std;

#define ENCLAVE_FILE _T("TDT_enclave.signed.dll") 

#ifdef UNICODE
#define CreateDirectory  CreateDirectoryW
#else
#define CreateDirectory  CreateDirectoryA
#endif // !UNICODE

#if defined FUNCTION_LEVEL_PROFILE

typedef struct server_profile {
	std::chrono::duration<double> create_enclave;
	std::chrono::duration<double> attestation[100];
	std::chrono::duration<double> receive_msg4[100];
	std::chrono::duration<double> verify_attstation[100];
	std::chrono::duration<double> enclave_cal_TDT;
	std::chrono::duration<double> enclave_encryption;

} s_p;
#endif

typedef struct socket_client_pair
{
	int socket_fd;
	int client_id;
	char username[128];
}S_C;

typedef struct server_context {
	int client_num;
	int account_count;
	int algo;
	int topK;
	int port;
	int request_summary;
	char **username;
	char **password;
	bool SSLenable;
	int compression;
	int segment_length;

	string resultFolder;

	char **data;
	int data_size;
	
	sgx_enclave_id_t eid;
	sgx_ra_context_t *enclaveContext;

	AnalysisMethod *analysisMethod;
}ServerContext;


int attestation(sgx_enclave_id_t enclave_id, sgx_ra_context_t *context, sgx_status_t status, Socket *S, int socket_fd, int client_id);
void PRINT_BYTE_ARRAY( FILE *file, void *mem, uint32_t len);
int initServerContext(ServerContext *context);
string CreateResultFolder();
string currentDateTime();

int InitEnclave(ServerContext *context);
int InitServerContextAfterConfig(ServerContext *context);
int WaitForClients(ServerContext *context);
int ReceiveDataFromClient(ServerContext *serverCtx);
int ProcessandSendResults(ServerContext *serverCtx);