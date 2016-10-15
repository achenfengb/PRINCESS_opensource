#pragma once
#include "ecp.h"
#include "service_provider.h"


#define SAMPLE_ECP256_KEY_SIZE             32
typedef struct sample_ec256_private_t
{
    uint8_t r[SAMPLE_ECP256_KEY_SIZE];
} sample_ec256_private_t;

// This is a context data structure used on SP side
typedef struct _sp_db_item_t
{
	sample_ec_pub_t             g_a;
	sample_ec_pub_t             g_b;
	sample_ec_key_128bit_t      vk_key;// Shared secret key for the REPORT_DATA
	sample_ec_key_128bit_t      mk_key;// Shared secret key for generating MAC's
	sample_ec_key_128bit_t      sk_key;// Shared secret key for encryption
	sample_ec_key_128bit_t      smk_key;// Used only for SIGMA protocol
	sample_ec_priv_t            b;
	sample_ps_sec_prop_desc_t   ps_sec_prop;
}sp_db_item_t;


#define SP_IV_SIZE 12

class DataEncryption
{
public:
	DataEncryption(void);
	~DataEncryption(void);

	int data_decryption(char* data, char* decrypted_data, int data_size, sp_db_item_t g_sp_db);
	int data_encryption(char* data, int data_size, char* data_encrypted, sp_db_item_t g_sp_db);

	int iv_counter;
};

