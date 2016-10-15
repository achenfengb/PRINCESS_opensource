#include <ctime>
#include <chrono>
#include "DataManagement.h"
#include "DataEncryption.h"
#include "Socket.h"
#include "ssl_client.h"

using namespace std::chrono;

#define MAX_FILE_PATH_LENGTH 2000
#define MAX_ACCOUNT_LENGTH 20
#define MAX_PRIV_KEY_LENGTH 65
#define MAX_ENCLAVE_ID_LENGTH 65
#define MAX_IP_LENGTH 30

typedef struct client_context {
	int max_timeout;
	int port;
	int parser;
	char server_IP[MAX_IP_LENGTH];
	char file_path_TDT[MAX_FILE_PATH_LENGTH];
	char file_path_freq[MAX_FILE_PATH_LENGTH];
	char private_Key[MAX_PRIV_KEY_LENGTH];
	char username[MAX_ACCOUNT_LENGTH];
	char password[MAX_ACCOUNT_LENGTH];
	sample_ec256_private_t g_sp_priv_key;
	sp_db_item_t g_sp_db;
	bool updateEncalve;
	char enclaveID[MAX_ENCLAVE_ID_LENGTH];

	bool SSLenable;
	int compression;
	int segmentLength;
	Socket *S;
	SSL_CTX *SSLctx;

	DataManagement *dataManager;
	DataEncryption *dataEncrypter;
}ClientContext;

typedef struct client_profile {
	duration<double> client_loadfile;
	duration<double> client_encryption;
	duration<double> waiting_result;
	duration<double> client_decryption;

} c_p;

sample_ec256_private_t convert_private_key(char *private_key);
int InitClientContext(ClientContext *context);
int InitClientContextAfterConfig(ClientContext *context);
int ConnectToServer(ClientContext *context);
int attestation_client(ClientContext *context);
int EncryptandSendData(ClientContext *context);
int assemble_msg4( ra_samp_response_header_t** pp_msg4, int* msg4_full_size, char* data, int data_size, ClientContext *context);
int ProcessResult(ClientContext *context);
void PrintTimeMeasurement();
int CloseConnection(ClientContext *context);