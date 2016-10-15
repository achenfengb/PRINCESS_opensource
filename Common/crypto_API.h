
#pragma once

#ifndef SAMPLE_CRYPTO_LIB
	//#define SAMPLE_CRYPTO_LIB
#endif

#ifndef TRUST_CRYPTO_LIB
	#define TRUST_CRYPTO_LIB
#endif

#include "dll.h"
#include  "cryptlib.h"
#include  "filters.h"
#include  "fips140.h"

#include "service_provider.h"
#include <sstream> 

#include <assert.h>

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include <cstdlib>
using std::exit;

#include  "osrng.h"
// using CryptoPP::AutoSeededX917RNG;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::AutoSeededX917RNG;

#include  "aes.h"
using CryptoPP::AES;

#include  "integer.h"
using CryptoPP::Integer;

#include  "sha.h"
using CryptoPP::SHA256;

#include  "filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;

#include  "files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include  "ec2n.h"
#include  "eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::EC2N;
using CryptoPP::EC2NPoint;
using CryptoPP::ECDH;
using CryptoPP::DL_GroupParameters_EC;

#if _MSC_VER <= 1200 // VS 6.0
using CryptoPP::ECDSA<ECP, SHA256>;
using CryptoPP::DL_GroupParameters_EC<ECP>;
#endif

#include  "secblock.h"
using CryptoPP::SecByteBlock;

#include  "oids.h"
using CryptoPP::OID;

// ASN1 is a namespace, not an object
#include  "asn.h"
using namespace CryptoPP::ASN1;

#include  "integer.h"
using CryptoPP::Integer;

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

using CryptoPP::CMAC;

         
#define trust_ec_pub_t          	sample_ec_pub_t          
#define trust_ps_sec_prop_desc_t	sample_ps_sec_prop_desc_t

#ifndef TRUST_FEBITSIZE
    #define TRUST_FEBITSIZE                    256
#endif

#define TRUST_ECP_KEY_SIZE                     (TRUST_FEBITSIZE/8)

typedef struct trust_ec_priv_t
{
    uint8_t r[TRUST_ECP_KEY_SIZE];
} trust_ec_priv_t;

typedef struct trust_ec_dh_shared_t
{
    uint8_t s[TRUST_ECP_KEY_SIZE];
}trust_ec_dh_shared_t;

typedef uint8_t trust_ec_key_128bit_t[16];

#define TRUST_EC_MAC_SIZE 16

typedef enum trust_status_t
{
    TRUST_SUCCESS                  = true,
	TRUST_FAILURE                  = false,
	TRUST_INTERNAL_ERROR
    //TRUST_ERROR_UNEXPECTED         ,      // Unexpected error
    //TRUST_ERROR_INVALID_PARAMETER  ,      // The parameter is incorrect
    //TRUST_ERROR_OUT_OF_MEMORY      ,      // Not enough memory is available to complete this operation

} trust_status_t;


#define TRUST_SHA256_HASH_SIZE            32
#define TRUST_ECP256_KEY_SIZE             32
#define TRUST_NISTP_ECP256_KEY_SIZE       (TRUST_ECP256_KEY_SIZE/sizeof(uint32_t))
#define TRUST_AESGCM_IV_SIZE              12
#define TRUST_AESGCM_KEY_SIZE             16
#define TRUST_AESGCM_MAC_SIZE             16
#define TRUST_CMAC_KEY_SIZE               16
#define TRUST_CMAC_MAC_SIZE               16
#define TRUST_AESCTR_KEY_SIZE             16

typedef struct trust_ec256_dh_shared_t
{
    uint8_t s[TRUST_ECP256_KEY_SIZE];
} trust_ec256_dh_shared_t;

typedef struct trust_ec256_ECDH_private_t
{
	uint8_t r[TRUST_ECP256_KEY_SIZE];
	ECDH < ECP >::Domain dhB;
	SecByteBlock privKey;
	SecByteBlock sharedKey;
} trust_ec256_ECDH_private_t;

typedef struct trust_ec256_ECDH_public_t
{
	uint8_t gx[TRUST_ECP256_KEY_SIZE];
    uint8_t gy[TRUST_ECP256_KEY_SIZE];
	SecByteBlock pubKey;
} trust_ec256_ECDH_public_t;

typedef struct trust_ec256_ECDSA_private_t
{
	uint8_t r[TRUST_ECP256_KEY_SIZE];
	ECDSA<ECP, CryptoPP::SHA256>::PrivateKey privateKey;
} trust_ec256_ECDSA_private_t;

typedef struct trust_ec256_ECDSA_public_t
{
	uint8_t gx[TRUST_ECP256_KEY_SIZE];
    uint8_t gy[TRUST_ECP256_KEY_SIZE];
	ECDSA<ECP, CryptoPP::SHA256>::PublicKey publicKey;
} trust_ec256_ECDSA_public_t;

typedef struct trust_ec256_signature_t
{
    uint32_t x[TRUST_NISTP_ECP256_KEY_SIZE];
    uint32_t y[TRUST_NISTP_ECP256_KEY_SIZE];
} trust_ec256_signature_t;

typedef void* trust_sha_state_handle_t;
typedef void* trust_cmac_state_handle_t;
typedef void* trust_ecc_state_handle_t;

typedef uint8_t trust_sha256_hash_t[TRUST_SHA256_HASH_SIZE];

typedef uint8_t trust_aes_gcm_128bit_key_t[TRUST_AESGCM_KEY_SIZE];
typedef uint8_t trust_aes_gcm_128bit_tag_t[TRUST_AESGCM_MAC_SIZE];
typedef uint8_t trust_cmac_128bit_key_t[TRUST_CMAC_KEY_SIZE];
typedef uint8_t trust_cmac_128bit_tag_t[TRUST_CMAC_MAC_SIZE];
typedef uint8_t trust_aes_ctr_128bit_key_t[TRUST_AESCTR_KEY_SIZE];

trust_status_t trust_rijndael128_cmac_msg(uint8_t* mac_key, 
										  uint8_t *p_data_buf,
										  int buf_size,
										  uint8_t *data_mac);

void trust_covert_endian(const byte *key_in, byte * key_out, int key_size);
trust_status_t trust_ecdsa_sign(const uint8_t *p_data, 
                                uint32_t data_size,  
                                trust_ec256_ECDSA_private_t *p_private,
                                trust_ec256_signature_t *p_signature);
bool test_verify_MSG(const uint8_t *p_data, 
                     uint32_t data_size,
					 trust_ec256_ECDSA_public_t *p_public,
					 const uint8_t *signature,
					 uint32_t signature_size);

bool trust_rijndael128GCM_decrypt(const trust_ec_key_128bit_t *p_key,
                                 const uint8_t *p_src,
                                 uint32_t src_len,
                                 uint8_t *p_dst,
                                 const uint8_t *p_iv,
                                 uint32_t iv_len,
                                 const uint8_t *p_aad,
                                 uint32_t aad_len,
                                 const uint8_t *p_in_mac);

bool trust_rijndael128GCM_encrypt(trust_ec_key_128bit_t *key,
                                 uint8_t *p_src,
                                 uint32_t src_len,
                                 uint8_t *p_dst,
                                 const uint8_t *iv,
                                 uint32_t iv_len,
                                 const uint8_t *p_aad,
                                 uint32_t aad_len,
                                 uint8_t *p_out_mac);



bool trust_rijndael128GCM_encrypt_1(trust_ec_key_128bit_t *key,
                                 uint8_t *p_src,
                                 uint32_t src_len,
                                 uint8_t *p_dst,
                                 const uint8_t *iv,
                                 uint32_t iv_len,
                                 const uint8_t *p_aad,
                                 uint32_t aad_len,
                                 uint8_t *p_out_mac);







void trust_covert_key_2_sgx(const Integer& key, byte * key_sgx, int key_size);

/* Populates private/public key pair - caller code allocates memory
* Parameters:
*	Return: trust_status_t  - TRUST_SUCCESS on success, error code otherwise.
*	Outputs: trust_ec256_private_t *p_private - Pointer to the private key
*			 trust_ec256_public_t *p_public - Pointer to the public key  */
trust_status_t trust_ecc256_create_key_pair_ECDSA(trust_ec256_ECDSA_private_t *p_private,
                                        trust_ec256_ECDSA_public_t *p_public);

trust_status_t trust_ecc256_create_key_pair_ECDH(trust_ec256_ECDH_private_t *p_private,
                                        trust_ec256_ECDH_public_t *p_public);

trust_status_t trust_ecc256_compute_shared_dhkey(trust_ec256_ECDH_private_t *p_private,
												 trust_ec256_ECDH_public_t  *pubA,
												 trust_ec256_dh_shared_t    *trust_dh_key);

/*
* Elliptic Curve Crytpography - Based on GF(p), 256 bit
*/
/* Allocates and initializes ecc context
* Parameters:
*	Return: trust_status_t  - TRUST_SUCCESS or failure as defined TRUST_Error.h
*/
trust_status_t trust_ecc256_open_context();


trust_status_t GeneratePrivateKey_ECDSA( const OID& oid, ECDSA<ECP, CryptoPP::SHA256>::PrivateKey& key );
trust_status_t GeneratePublicKey_ECDSA( const ECDSA<ECP, CryptoPP::SHA256>::PrivateKey& privateKey, ECDSA<ECP, CryptoPP::SHA256>::PublicKey& publicKey );

void SavePrivateKey( const string& filename, const ECDSA<ECP, CryptoPP::SHA256>::PrivateKey& key );
void SavePublicKey( const string& filename, const ECDSA<ECP, CryptoPP::SHA256>::PublicKey& key );
void LoadPrivateKey( const string& filename, ECDSA<ECP, CryptoPP::SHA256>::PrivateKey& key );
void LoadPublicKey( const string& filename, ECDSA<ECP, CryptoPP::SHA256>::PublicKey& key );

void SavePrivateKey( const string& filename, const ECDSA<ECP, CryptoPP::SHA256>::PrivateKey& key );
void SavePublicKey( const string& filename, const ECDSA<ECP, CryptoPP::SHA256>::PublicKey& key );
void LoadPrivateKey( const string& filename, ECDSA<ECP, CryptoPP::SHA256>::PrivateKey& key );
void LoadPublicKey( const string& filename, ECDSA<ECP, CryptoPP::SHA256>::PublicKey& key );

void PrintDomainParameters( const ECDSA<ECP, CryptoPP::SHA256>::PrivateKey& key );
void PrintDomainParameters( const ECDSA<ECP, CryptoPP::SHA256>::PublicKey& key );
void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params );
void PrintPrivateKey( const ECDSA<ECP, CryptoPP::SHA256>::PrivateKey& key );
void PrintPublicKey( const ECDSA<ECP, CryptoPP::SHA256>::PublicKey& key );

bool SignMessage( const ECDSA<ECP, CryptoPP::SHA256>::PrivateKey& key, const string& message, string& signature );
bool VerifyMessage( const ECDSA<ECP, CryptoPP::SHA256>::PublicKey& key, const string& message, const string& signature );
