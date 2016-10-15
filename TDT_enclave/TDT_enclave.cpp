#include "TDT_enclave_t.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>      /* vsnprintf */
#include <string.h>
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "TDT.h"
#include "Debug_Flags.h"
#include "range_code.h"



#ifdef _MSC_VER
#pragma warning(push)
#pragma warning ( disable:4127 )
#endif

// This is the public EC key of the SP. The corresponding private EC key is
// used by the SP to sign data used in the remote attestation SIGMA protocol
// to sign channel binding data in MSG2. A successful verification of the
// signature confirms the identity of the SP to the ISV app in remote
// attestation secure channel binding. The public EC key should be hardcoded in
// the enclave or delivered in a trustworthy manner. The use of a spoofed public
// EC key in the remote attestation with secure channel binding session may lead
// to a security compromise. Every different SP the enlcave communicates to
// must have a unique SP public key. Delivery of the SP public key is
// determined by the ISV. The TKE SIGMA protocl expects an Elliptical Curve key
// based on NIST P-256


//global buffer for eompression
extern unsigned char* g_buffer;
extern int current_byte;

int * iv_counter;
bool iv_counter_init_flag = false;

//#define PAGE_ATTACK_PROTECTION_RANDOM_ACESS
#define PAGE_ATTACK_PROTECTION_WITHIN_PAGE
//#define NON_PAGE_ATTACK_PPROTECTION
#define LOOKUP_TABLE_ENABLE
//#define LOOKUP_TABLE_ENABLE

#ifdef PAGE_ATTACK_PROTECTION_RANDOM_ACESS
#define PAGE_ATTACK_PROTECTION
#endif

#ifdef PAGE_ATTACK_PROTECTION_WITHIN_PAGE
#include <math.h>
#define PAGE_ATTACK_PROTECTION
#define PAGE_SIZE 0x1000
const int PAGE_MAX_SNP = PAGE_SIZE / sizeof(TDT_OUTPUT_TYPE);
#endif

#ifdef PAGE_ATTACK_PROTECTION_RANDOM_ACESS
#define C 4
#include <math.h>
#endif

/* 
* printf: 
*   Invokes OCALL to display the enclave buffer to the terminal.
*   Only used for debug purpose....
*/
void printf(const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

static const sgx_ec256_public_t g_sp_pub_key[] = {
	//pub_key No1  (the original)
	{
		{
			0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
				0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
				0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
				0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
		},
		{
			0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
				0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
				0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
				0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
			}
	},

		//pub_key No2
	{
		{
			0xd1, 0x1e, 0x95, 0x94, 0xec, 0xa0, 0x1d, 0xaa, 
				0x8a, 0x79, 0x39, 0xe9, 0x46, 0xb0, 0x33, 0xc2, 
				0xf3, 0x23, 0xc5, 0x27, 0x34, 0x8e, 0x40, 0xb5, 
				0xcd, 0x23, 0xa5, 0xcc, 0xea, 0x16, 0x1a, 0xa0
		},
		{
			0x44, 0xb3, 0x4a, 0xa1, 0x84, 0x7b, 0x81, 0x82, 
				0x50, 0x16, 0xe2, 0x17, 0xd3, 0xcd, 0x21, 0x77, 
				0xdd, 0x41, 0x05, 0xad, 0x9f, 0x32, 0xec, 0x49, 
				0x1f, 0x29, 0x2a, 0xfa, 0xf8, 0xa7, 0x6c, 0xdf
			}
	},

		//pub_key No3
	{
		{
			0x9d, 0x5d, 0xcf, 0x57, 0x4d, 0x94, 0x6d, 0x90, 
				0x21, 0x52, 0xaf, 0xb5, 0x28, 0x5e, 0x8e, 0xff, 
				0xa8, 0xe2, 0x37, 0x3d, 0x39, 0x2e, 0x5b, 0xc0, 
				0x1a, 0x8d, 0x16, 0xe0, 0xac, 0x89, 0xa4, 0x94
		},
		{
			0x77, 0x5b, 0xff, 0x94, 0xc5, 0xc3, 0x86, 0x53, 
				0xc3, 0x6c, 0x2e, 0xfb, 0x39, 0x13, 0xb3, 0xcd, 
				0x82, 0x61, 0x7d, 0x3b, 0x16, 0xc4, 0x7e, 0x26, 
				0xd7, 0x43, 0x44, 0x11, 0xa8, 0xc5, 0xee, 0x21
			}
	},
		//pub_key No4
	{
		{
			0x63, 0x45, 0x44, 0x1c, 0x72, 0x4b, 0xdc, 0x82, 
				0xb3, 0xbb, 0xf2, 0x34, 0x52, 0x88, 0x3c, 0xbf, 
				0x99, 0x09, 0xdf, 0x47, 0x35, 0x6b, 0x88, 0xde, 
				0x74, 0xff, 0x12, 0x39, 0x10, 0xda, 0xf5, 0x53
		},
		{
			0x5d, 0x2e, 0x6f, 0xae, 0xa1, 0x73, 0x75, 0x75, 
				0xaf, 0x5c, 0x34, 0x6d, 0x5c, 0x5c, 0x6a, 0x42, 
				0x94, 0x96, 0x9f, 0xe4, 0x30, 0x18, 0x12, 0x2d, 
				0x36, 0x9d, 0x13, 0xb6, 0x3e, 0xbe, 0x7d, 0xcc
			}
	},
		//pub_key No5
	{
		{
			0xf9, 0x7b, 0xe1, 0x11, 0xa1, 0xf9, 0xd6, 0x15, 
				0x7f, 0xc0, 0x94, 0x62, 0x9f, 0x13, 0xa9, 0x93, 
				0x90, 0x8a, 0xf8, 0x86, 0xa4, 0xcb, 0xe8, 0x56, 
				0x1e, 0xbd, 0x2d, 0x70, 0x4b, 0xe8, 0x32, 0x71
		},
		{
			0xa6, 0x16, 0x2f, 0xea, 0x2f, 0xaf, 0x8e, 0x23, 
				0x77, 0x41, 0xff, 0x0e, 0xcb, 0x2c, 0xce, 0x72, 
				0x90, 0x43, 0x55, 0xff, 0xc2, 0xf0, 0x5d, 0x09, 
				0x1f, 0x98, 0x1a, 0xfb, 0x5b, 0x32, 0x05, 0xec
			}
	},
		//pub_key No6
	{
		{
			0xeb, 0xf0, 0x06, 0x5a, 0x9a, 0x96, 0x58, 0x73, 
				0x66, 0x41, 0xc9, 0x3b, 0x82, 0x2d, 0x4f, 0x22, 
				0x65, 0xe4, 0x95, 0x4a, 0xef, 0xcf, 0x8e, 0xac, 
				0x76, 0x5b, 0xb8, 0x52, 0x17, 0xa6, 0xcb, 0x29
		},
		{
			0x5e, 0x52, 0xdc, 0x4b, 0xe5, 0x15, 0x56, 0xec, 
				0xe8, 0x13, 0x74, 0xd7, 0x4b, 0x17, 0x8a, 0xed, 
				0x87, 0xfa, 0x92, 0x82, 0xf5, 0x35, 0xcc, 0x5d, 
				0xfc, 0xfd, 0xd5, 0x0e, 0x31, 0x69, 0x71, 0xe0
			}
	},
		//pub_key No7
	{
		{
			0x04, 0xda, 0xe0, 0x04, 0xea, 0xc2, 0x28, 0x7e, 
				0xaa, 0x0b, 0xdd, 0x75, 0x16, 0x79, 0x48, 0x39, 
				0xf2, 0xd6, 0x54, 0xeb, 0x67, 0x5f, 0x17, 0x59, 
				0x59, 0xa3, 0xd9, 0xe2, 0x07, 0xad, 0x9c, 0x10
		},
		{
			0xbc, 0xfb, 0xe5, 0xa0, 0x24, 0xbc, 0x2a, 0xd4, 
				0xb1, 0x6a, 0xcb, 0xf7, 0x68, 0xc2, 0x78, 0x63, 
				0xc3, 0x9c, 0xdd, 0x7a, 0xcf, 0x33, 0x61, 0x8a, 
				0x69, 0xcc, 0xc8, 0xb1, 0xf7, 0x3e, 0x09, 0xd2
			}
	},
		//pub_key No8
	{
		{
			0x69, 0x1e, 0x08, 0xd0, 0xaa, 0x42, 0x19, 0x73, 
				0x69, 0x8a, 0x77, 0xbc, 0x0a, 0x7f, 0x66, 0xe9, 
				0xb1, 0x8f, 0x6b, 0x7d, 0x20, 0x8d, 0x39, 0x6f, 
				0xee, 0x81, 0x5c, 0x05, 0xe7, 0x19, 0x98, 0x3e
		},
		{
			0xd1, 0x65, 0x39, 0xf4, 0xd8, 0xba, 0x91, 0x7d, 
				0x41, 0x93, 0xd4, 0x86, 0x16, 0x96, 0xf3, 0xd1, 
				0x36, 0x5b, 0x22, 0x3e, 0x8f, 0x98, 0x77, 0x1c, 
				0x88, 0x78, 0x11, 0xd7, 0xc8, 0xb0, 0xd2, 0x5a
			}
	},
		//pub_key No9
	{
		{
			0x96, 0xf7, 0xc9, 0x4e, 0xe4, 0x4d, 0xb1, 0xfb, 
				0x72, 0xbd, 0x68, 0x00, 0x15, 0x77, 0x4d, 0x8d, 
				0xd6, 0x14, 0x31, 0x51, 0x20, 0x8c, 0xce, 0xac, 
				0x77, 0x6d, 0x04, 0xea, 0x71, 0x15, 0x2c, 0xe0
		},
		{
			0xcb, 0x94, 0x4a, 0x2d, 0x99, 0x28, 0xc9, 0xa5, 
				0xb7, 0x53, 0x82, 0x12, 0xcf, 0x1b, 0x3f, 0xd0, 
				0xf9, 0xb7, 0x78, 0x80, 0xe4, 0xca, 0x58, 0x6e, 
				0xe0, 0xa0, 0xa1, 0xcd, 0xc5, 0xb0, 0x5f, 0xe0
			}
	},
		//pub_key No10
	{
		{
			0x71, 0x9b, 0xbc, 0x8e, 0x48, 0x05, 0x6d, 0xff, 
				0xf2, 0xd5, 0x58, 0x72, 0x06, 0x7f, 0x8f, 0x14, 
				0x5b, 0xed, 0xc5, 0xcd, 0xe4, 0xda, 0xe9, 0x6f, 
				0x4b, 0x23, 0x12, 0x3f, 0x66, 0xae, 0x48, 0x7b
		},
		{
			0x3e, 0x56, 0xae, 0x4e, 0xa1, 0x96, 0x7f, 0xe7, 
				0x95, 0x5e, 0x40, 0xff, 0xdc, 0xc5, 0x51, 0x76, 
				0xbd, 0x78, 0x7f, 0x45, 0xbe, 0x6b, 0xe2, 0xb6, 
				0x2d, 0x2b, 0x5c, 0xa6, 0x45, 0xe2, 0x3d, 0x2b
			}
	},
		//pub_key No11
	{
		{
			0xd7, 0x79, 0x7f, 0x71, 0x69, 0x10, 0x3e, 0x11, 
				0x96, 0xbb, 0xc3, 0x89, 0xd8, 0x64, 0xd7, 0xa9, 
				0xde, 0x3b, 0xb5, 0x68, 0xab, 0x78, 0x14, 0x42, 
				0x53, 0xbc, 0x89, 0x5e, 0x34, 0x30, 0x8f, 0x2b
		},
		{
			0x79, 0x13, 0xc1, 0x51, 0xdb, 0x04, 0x19, 0x91, 
				0xcf, 0x40, 0xea, 0x29, 0x22, 0x36, 0x94, 0xa8, 
				0xb0, 0xd0, 0xdb, 0x96, 0x67, 0x7d, 0x97, 0xb5, 
				0x87, 0x9e, 0x13, 0x86, 0x83, 0x43, 0x20, 0xb5
			}
	},
		//pub_key No12
	{
		{
			0x78, 0xcc, 0xbb, 0x16, 0x57, 0xf2, 0x28, 0xcc, 
				0x94, 0x72, 0x75, 0x51, 0xc2, 0x15, 0x6e, 0x10, 
				0x13, 0x5b, 0x2b, 0x76, 0x73, 0x11, 0x8d, 0x80, 
				0x22, 0xbc, 0x43, 0xa6, 0x5f, 0xe4, 0x95, 0xd5
		},
		{
			0xdf, 0xf1, 0x70, 0x67, 0xd6, 0xe8, 0x19, 0x64, 
				0x1b, 0x80, 0x82, 0x5d, 0x3e, 0x97, 0x95, 0xb3, 
				0x26, 0x81, 0x8d, 0x0b, 0xe1, 0x15, 0x47, 0x72, 
				0x11, 0x2d, 0xe7, 0xdc, 0x29, 0x53, 0xb4, 0x12
			}
	}
};



/*static double* array_b_seg;
static double* array_c_seg;
static double* result_topK;
static int* index;
static bool if_allocated = false;
static bool if_allocated_result = false;
static int length = 0;*/

// Used to store the secret passed by the SPs
// 0x01,0x02,0x03,0x04,0x0x5,0x0x6,0x0x7
//uint8_t g_secret[8] = {0};

// This ecall is a wrapper of sgx_ra_init to create the trusted
// KE exchange key context needed for the remote attestation
// SIGMA API's. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
// @param b_pse Indicates whether the ISV app is using the
//              platform services.
// @param p_context Pointer to the location where the returned
//                  key context is to be copied.
// @param client_id
//
// @return Any error return from the create PSE session if b_pse
//         is true.
// @return Any error returned from the trusted key exchange API
//         for creating a key context.

sgx_status_t enclave_init_ra(
	int b_pse,
	int client_id,
	sgx_ra_context_t *p_context)
{
	// isv enclave call to trusted key exchange library.
	sgx_status_t ret;
	if(b_pse)
	{
		int busy_retry_times = 2;
		do{
			ret = sgx_create_pse_session();
		}while (ret == SGX_ERROR_BUSY && busy_retry_times--);
		if (ret != SGX_SUCCESS)
			return ret;
	}



	ret = sgx_ra_init(&g_sp_pub_key[client_id], b_pse, p_context);
	if(b_pse)
	{
		sgx_close_pse_session();
		return ret;
	}
	return ret;
}


// Closes the tKE key context used during the SIGMA key
// exchange.
//
// @param context The trusted KE library key context.
//
// @return Return value from the key context close API

sgx_status_t SGXAPI enclave_ra_close(
	sgx_ra_context_t context)
{
	sgx_status_t ret;
	ret = sgx_ra_close(context);
	return ret;
}


// Verify the mac sent in att_result_msg from the SP using the
// MK key. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
//
// @param context The trusted KE library key context.
// @param p_message Pointer to the message used to produce MAC
// @param message_size Size in bytes of the message.
// @param p_mac Pointer to the MAC to compare to.
// @param mac_size Size in bytes of the MAC
//
// @return SGX_ERROR_INVALID_PARAMETER - MAC size is incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESCMAC function.
// @return SGX_ERROR_MAC_MISMATCH - MAC compare fails.

sgx_status_t verify_att_result_mac(sgx_ra_context_t context,
								   uint8_t* p_message,
								   size_t message_size,
								   uint8_t* p_mac,
								   size_t mac_size)
{
	sgx_status_t ret;
	sgx_ec_key_128bit_t mk_key;

	if(mac_size != sizeof(sgx_mac_t))
	{
		ret = SGX_ERROR_INVALID_PARAMETER;
		return ret;
	}
	if(message_size > UINT32_MAX)
	{
		ret = SGX_ERROR_INVALID_PARAMETER;
		return ret;
	}

	do {
		uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

		ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
		if(SGX_SUCCESS != ret)
		{
			break;
		}
		ret = sgx_rijndael128_cmac_msg(&mk_key,
			p_message,
			(uint32_t)message_size,
			&mac);
		if(SGX_SUCCESS != ret)
		{
			break;
		}
		if(0 == consttime_memequal(p_mac, mac, sizeof(mac)))
		{
			ret = SGX_ERROR_MAC_MISMATCH;
			break;
		}

	}
	while(0);

	return ret;
}


TDT_INPUT_TYPE * buffer_b, * buffer_c, *buffer_a1, *buffer_a2;
unsigned L, parties_num, K, updating_top_k_flag, current_L0;
TDT_OUTPUT_INDEX_TYPE index_pri;

#ifdef PAGE_ATTACK_PROTECTION
TDT_INPUT_TYPE * buffer_b0, * buffer_c0, *buffer_a10, *buffer_a20;
TDT_OUTPUT_TYPE * buffer_TDT, *buffer_TDT0;
TDT_OUTPUT_INDEX_TYPE * index_buffer, *index_buffer0;
unsigned L_BUFFER, L0_BUFFER;
#endif

#ifdef PAGE_ATTACK_PROTECTION_WITHIN_PAGE
TDT_INPUT_TYPE* array_b_0_tmp;
TDT_INPUT_TYPE* array_c_0_tmp;
TDT_INPUT_TYPE* array_a1_0_tmp; 
TDT_INPUT_TYPE* array_a2_0_tmp; 

int ONE_PAGE_SNP_LEN = 0;
//= PAGE_MAX_SNP - K;


void updateBC_PER_PAGE(TDT_INPUT_TYPE* array_b_0, TDT_INPUT_TYPE* array_c_0, TDT_INPUT_TYPE* array_a1_0, TDT_INPUT_TYPE* array_a2_0, int L0);
char *_buffer = (char*)calloc(PAGE_SIZE * 7, 1);

template <typename T>
void swap1(T* a, T* b)
{
	T c;
	c = *a;
	*a = *b;
	*b = c;
}
#endif

#ifdef NON_PAGE_ATTACK_PPROTECTION
TDT_OUTPUT_TYPE * TDT_top_K;
TDT_INPUT_TYPE *B_topK, *C_topK, *A1_topK, *A2_topK;
TDT_OUTPUT_INDEX_TYPE * TDT_top_K_index;
#endif


bool initiallized_flag = false;

void initializeEnclave(unsigned _L, unsigned _parties_num, unsigned _K);
void updateBC(TDT_INPUT_TYPE* array_b_0, TDT_INPUT_TYPE* array_c_0, TDT_INPUT_TYPE* array_a1_0, TDT_INPUT_TYPE* array_a2_0, int L0);


void bzeros(TDT_INPUT_TYPE* array0, unsigned L);
void updateSum(TDT_INPUT_TYPE* array_b0, TDT_INPUT_TYPE* array_c0, TDT_INPUT_TYPE* array_a1_0, TDT_INPUT_TYPE* array_a2_0, unsigned L0);
TDT_OUTPUT_TYPE calTDT(TDT_INPUT_TYPE b, TDT_INPUT_TYPE c);
void updateTopK();
void freeBC();

#ifdef PAGE_ATTACK_PROTECTION
void resetIndex(TDT_OUTPUT_INDEX_TYPE* index, int num, TDT_OUTPUT_INDEX_TYPE start0);
void calTDTs();
#endif

#ifdef PAGE_ATTACK_PROTECTION_RANDOM_ACESS
void compareRegions(int s, int t, int offset);
void permuteRandom(int* a, int len);
void compareExchange(int i, int j);
void exchange(int i, int j);
void exchange1(int* a, int i, int j);
#endif

#ifdef NON_PAGE_ATTACK_PPROTECTION
void insertArray(TDT_OUTPUT_TYPE tdt, TDT_OUTPUT_INDEX_TYPE tdt_index, TDT_INPUT_TYPE b, TDT_INPUT_TYPE c, TDT_INPUT_TYPE a1, TDT_INPUT_TYPE a2, int pos);
int getIndex(TDT_OUTPUT_TYPE val);
#endif


//void getKLargest(TDT_OUTPUT_TYPE* tdts_K_largest, TDT_OUTPUT_INDEX_TYPE* tdts_K_largest_index, int K0);


void initializeEnclave(unsigned _L, unsigned _parties_num, unsigned _K){
	L = _L;
	parties_num = _parties_num;
	K = _K;
	updating_top_k_flag = 0;
	index_pri = 0;

#ifdef PAGE_ATTACK_PROTECTION_WITHIN_PAGE
	ONE_PAGE_SNP_LEN = PAGE_MAX_SNP - K;

	char* add_temp;
	int temp = ((unsigned long)_buffer)%PAGE_SIZE;

	if(temp){
		add_temp = _buffer - temp + PAGE_SIZE;
	}else{
		add_temp = _buffer;
	}
	buffer_b = (TDT_INPUT_TYPE*)add_temp;
	add_temp += PAGE_SIZE;
	buffer_c = (TDT_INPUT_TYPE*)add_temp;
	add_temp += PAGE_SIZE;
	buffer_a1 = (TDT_INPUT_TYPE*)add_temp;
	add_temp += PAGE_SIZE;
	buffer_a2 = (TDT_INPUT_TYPE*)add_temp;
	add_temp += PAGE_SIZE;
	buffer_TDT = (TDT_OUTPUT_TYPE*)add_temp;
	add_temp += PAGE_SIZE;
	index_buffer = (TDT_OUTPUT_INDEX_TYPE *)add_temp;

	array_b_0_tmp = (TDT_INPUT_TYPE*)calloc(_L, sizeof(TDT_INPUT_TYPE));
	array_c_0_tmp = (TDT_INPUT_TYPE*)calloc(_L, sizeof(TDT_INPUT_TYPE));
	array_a1_0_tmp = (TDT_INPUT_TYPE*)calloc(_L, sizeof(TDT_INPUT_TYPE));
	array_a2_0_tmp = (TDT_INPUT_TYPE*)calloc(_L, sizeof(TDT_INPUT_TYPE));
#endif

#ifdef PAGE_ATTACK_PROTECTION_RANDOM_ACESS
	L_BUFFER = 1 << ((int)ceil(log((double)(L + K))/log(2.0)));
	L0_BUFFER = L_BUFFER - K;
	buffer_b = (TDT_INPUT_TYPE*)calloc(L_BUFFER, sizeof(TDT_INPUT_TYPE));
	buffer_c = (TDT_INPUT_TYPE*)calloc(L_BUFFER, sizeof(TDT_INPUT_TYPE));
	buffer_a1 = (TDT_INPUT_TYPE*)calloc(L_BUFFER, sizeof(TDT_INPUT_TYPE));
	buffer_a2 = (TDT_INPUT_TYPE*)calloc(L_BUFFER, sizeof(TDT_INPUT_TYPE));
	buffer_TDT = (TDT_OUTPUT_TYPE *)calloc(L_BUFFER, sizeof(TDT_OUTPUT_TYPE));

	index_buffer = (TDT_OUTPUT_INDEX_TYPE *)calloc(L_BUFFER, sizeof(TDT_OUTPUT_INDEX_TYPE));
#endif

#ifdef PAGE_ATTACK_PROTECTION
	bzeros(buffer_b, L_BUFFER);
	bzeros(buffer_c, L_BUFFER);

	buffer_b0 = buffer_b + _K;
	buffer_c0 = buffer_c + _K;
	buffer_a10 = buffer_a1 + _K;
	buffer_a20 = buffer_a2 + _K;
	buffer_TDT0 = buffer_TDT + _K;
	index_buffer0 = index_buffer + _K;
#endif

#ifdef NON_PAGE_ATTACK_PPROTECTION
	buffer_b = (TDT_INPUT_TYPE*)calloc(_L, sizeof(TDT_INPUT_TYPE));
	buffer_c = (TDT_INPUT_TYPE*)calloc(_L, sizeof(TDT_INPUT_TYPE));
	buffer_a1 = (TDT_INPUT_TYPE*)calloc(_L, sizeof(TDT_INPUT_TYPE));
	buffer_a2 = (TDT_INPUT_TYPE*)calloc(_L, sizeof(TDT_INPUT_TYPE));
	TDT_top_K = (TDT_OUTPUT_TYPE *)calloc(_K, sizeof(TDT_OUTPUT_TYPE));
	B_topK = (TDT_INPUT_TYPE*)calloc(_K, sizeof(TDT_INPUT_TYPE));
	C_topK = (TDT_INPUT_TYPE*)calloc(_K, sizeof(TDT_INPUT_TYPE));
	A1_topK = (TDT_INPUT_TYPE*)calloc(_K, sizeof(TDT_INPUT_TYPE));
	A2_topK = (TDT_INPUT_TYPE*)calloc(_K, sizeof(TDT_INPUT_TYPE));

	TDT_top_K_index = (TDT_OUTPUT_INDEX_TYPE *)calloc(_K, sizeof(TDT_OUTPUT_INDEX_TYPE));
#endif
}

void updateBC(TDT_INPUT_TYPE* array_b_0, TDT_INPUT_TYPE* array_c_0, TDT_INPUT_TYPE* array_a1_0, TDT_INPUT_TYPE* array_a2_0, int L0){
	if(updating_top_k_flag == 0){
		current_L0 = L0;
#ifdef PAGE_ATTACK_PROTECTION		
		bzeros(buffer_b0, L0_BUFFER);
		bzeros(buffer_c0, L0_BUFFER);
		bzeros(buffer_a10, L0_BUFFER);
		bzeros(buffer_a20, L0_BUFFER);
		resetIndex(index_buffer0, current_L0, index_pri);
#endif

#ifdef NON_PAGE_ATTACK_PPROTECTION
		bzeros(buffer_b, L);
		bzeros(buffer_c, L);
		bzeros(buffer_a1, L);
		bzeros(buffer_a2, L);
#endif
	}

	updateSum(array_b_0, array_c_0, array_a1_0, array_a2_0, L0);

	if(updating_top_k_flag  == parties_num - 1){
		updating_top_k_flag = -1;
#ifdef PAGE_ATTACK_PROTECTION
		calTDTs();
#endif
		updateTopK();
		index_pri += current_L0;
	}
	updating_top_k_flag++;
}

/*void getKLargest(TDT_OUTPUT_TYPE* tdts_K_largest, TDT_OUTPUT_INDEX_TYPE* tdts_K_largest_index, int K0){
for(int k = 0; k < K; k++){
*(tdts_K_largest + k) = *(TDT_top_K + k);
*(tdts_K_largest_index + k) = *(TDT_top_K_index + k);
}
}*/

#ifdef PAGE_ATTACK_PROTECTION
void calTDTs()
{
	TDT_OUTPUT_TYPE *buffer_TDT0_tmp = buffer_TDT0;
	TDT_INPUT_TYPE *buffer_b0_tmp = buffer_b0;
	TDT_INPUT_TYPE *buffer_c0_tmp = buffer_c0;

	for(int n = 0; n < current_L0; n++) *buffer_TDT0_tmp++ = calTDT(*buffer_b0_tmp++, *buffer_c0_tmp++);
}

void resetIndex(TDT_OUTPUT_INDEX_TYPE* index, int num, TDT_OUTPUT_INDEX_TYPE start0)
{
	for(int n = 0; n < num; n++) *index++ = start0++;
}
#endif

#ifdef PAGE_ATTACK_PROTECTION_RANDOM_ACESS
void compareRegions(int s, int t, int offset)
{
	int* mate = new int[offset];
	for(int count = 0; count < C; count++)
	{
		for(int i = 0; i < offset; i++)
			mate[i] = i;
		permuteRandom(mate, offset);
		for(int i = 0; i < offset; i++)
			compareExchange(s + i, t + mate[i]);
	}

	delete[] mate;
}

void permuteRandom(int* a, int len)
{
	uint32_t val; 
	 
	for(int i = 0; i < len; i++)
	{
		sgx_read_rand((unsigned char *) &val, 4);
		exchange1(a, i, val%(len - i) + i);
	}
}

void compareExchange(int i, int j)
{
	if(((i < j)&&(buffer_TDT[i] < buffer_TDT[j])) || ((i > j) && (buffer_TDT[i] > buffer_TDT[j])))
	{
		exchange(i, j);
	}
}

void exchange(int i, int j)
{
	TDT_INPUT_TYPE temp0;
	TDT_OUTPUT_TYPE temp1;
	TDT_OUTPUT_INDEX_TYPE temp2;

	temp0 = buffer_b[i];
	buffer_b[i] = buffer_b[j];
	buffer_b[j] = temp0;

	temp0 = buffer_c[i];
	buffer_c[i] = buffer_c[j];
	buffer_c[j] = temp0;

	temp0 = buffer_a1[i];
	buffer_a1[i] = buffer_a1[j];
	buffer_a1[j] = temp0;

	temp0 = buffer_a2[i];
	buffer_a2[i] = buffer_a2[j];
	buffer_a2[j] = temp0;

	temp1 = buffer_TDT[i];
	buffer_TDT[i] = buffer_TDT[j];
	buffer_TDT[j] = temp1;

	temp2 = index_buffer[i];
	index_buffer[i] = index_buffer[j];
	index_buffer[j] = temp2;

}

void exchange1(int* a, int i, int j)
{
	int temp = a[i];
	a[i] = a[j];
	a[j] = temp;
}
#endif

#ifdef NON_PAGE_ATTACK_PPROTECTION
int getIndex(TDT_OUTPUT_TYPE val){
	int retPos = -1;
	for(int k = K - 1; k >= 0; k-- ){
		if(val > TDT_top_K[k]){
			retPos = k;
		}else{
			break;
		}
	}
	return retPos;
}

void insertArray(TDT_OUTPUT_TYPE tdt, TDT_OUTPUT_INDEX_TYPE tdt_index, TDT_INPUT_TYPE b, TDT_INPUT_TYPE c, TDT_INPUT_TYPE a1, TDT_INPUT_TYPE a2, int pos){
	if(pos > K - 2){
		*(TDT_top_K + K - 1) = tdt;
		*(B_topK + K -1) = b;
		*(C_topK + K -1) = c;
		*(A1_topK + K -1) = a1;
		*(A2_topK + K -1) = a2;
		*(TDT_top_K_index + K - 1) = tdt_index + index_pri;
		return;
	}
	for(int i = K - 1; i > pos; i--){
		*(TDT_top_K + i) = *(TDT_top_K + i - 1);
		*(B_topK + i) = *(B_topK + i -1);
		*(C_topK + i) = *(C_topK + i -1);
		*(A1_topK + i) = *(A1_topK + i -1);
		*(A2_topK + i) = *(A2_topK + i -1);
		*(TDT_top_K_index + i) = *(TDT_top_K_index + i - 1);
	}

	*(TDT_top_K + pos) = tdt;
	*(B_topK + pos) = b;
	*(C_topK + pos) = c;
	*(A1_topK + pos) = a1;
	*(A2_topK + pos) = a2;
	*(TDT_top_K_index + pos) = tdt_index + index_pri;
}
#endif

TDT_OUTPUT_TYPE calTDT(TDT_INPUT_TYPE b, TDT_INPUT_TYPE c){
	return ((TDT_OUTPUT_TYPE)(b - c) * (b - c))/ (b + c);
}

void bzeros(TDT_INPUT_TYPE* array0, unsigned L0){
	
	memset(array0, '\0', sizeof(TDT_INPUT_TYPE)*L0);
}

void updateSum(TDT_INPUT_TYPE* array_b0, TDT_INPUT_TYPE* array_c0, TDT_INPUT_TYPE* array_a1_0, TDT_INPUT_TYPE* array_a2_0, unsigned L0){
#ifdef PAGE_ATTACK_PROTECTION_RANDOM_ACESS
	for(int i = 0; i < L0; i++){
		*(buffer_b0+i) += *array_b0++;
		*(buffer_c0+i) += *array_c0++;
		*(buffer_a10+i) += *array_a1_0++;
		*(buffer_a20+i) += *array_a2_0++;
	}
#endif

#ifdef PAGE_ATTACK_PROTECTION_WITHIN_PAGE
	for(int i = 0; i < L0; i++){
		*(array_b_0_tmp+i) += *array_b0++;
		*(array_c_0_tmp+i) += *array_c0++;
		*(array_a1_0_tmp+i) += *array_a1_0++;
		*(array_a2_0_tmp+i) += *array_a2_0++;
	}
#endif

#ifdef NON_PAGE_ATTACK_PPROTECTION
	for(int i = 0; i < L0; i++){
		*(buffer_b+i) += *array_b0++;
		*(buffer_c+i) += *array_c0++;
		*(buffer_a1+i) += *array_a1_0++;
		*(buffer_a2+i) += *array_a2_0++;
	}
#endif
}


void updateTopK(){
#ifdef PAGE_ATTACK_PROTECTION_RANDOM_ACESS
	int len = L_BUFFER;
	for(int offset = len/2 ; offset > 0; offset/= 2)
	{
		for(int i = 0; i < len - offset; i+= offset)
			compareRegions(i, i + offset, offset);

		for(int i = len - offset; i >= offset; i -= offset)
			compareRegions(i - offset, i, offset);

		for(int i = 0; i < len - 3 * offset; i += offset)
			compareRegions(i, i + 3 * offset, offset);

		for(int i = 0; i < len - 2 * offset; i += offset)
			compareRegions(i, i + 2 * offset, offset);

		for(int i = 0; i < len; i += 2*offset)
			compareRegions(i, i+ offset, offset);

		for(int i = offset; i < len - offset; i += 2 * offset)
			compareRegions(i, i + offset, offset);
	}
#endif

#ifdef NON_PAGE_ATTACK_PPROTECTION
	for(int i = 0; i < current_L0; i++){
		TDT_OUTPUT_TYPE tdt = calTDT(*(buffer_b+i), *(buffer_c+i));
		int pos = getIndex(tdt);
		if(pos >= 0){
			insertArray(tdt, i, *(buffer_b+i), *(buffer_c+i), *(buffer_a1+i), *(buffer_a2+i), pos);
		}
	}
#endif

#ifdef PAGE_ATTACK_PROTECTION_WITHIN_PAGE
	for(int i = 0; i < current_L0; i++){
		*buffer_TDT0 = *(buffer_TDT0 + i);
		*buffer_b0 = *(buffer_b0 + i);
		*buffer_c0 = *(buffer_c0 + i);
		*buffer_a10 = *(buffer_a10 + i);
		*buffer_a20 = *(buffer_a20 + i);
		*index_buffer0 = *(index_buffer0 + i);

		for(int j = K; j >0; j--){
			if(*(buffer_TDT + j) > *(buffer_TDT + j - 1)){
				swap1(buffer_TDT + j, buffer_TDT + j - 1);
				swap1(buffer_b + j, buffer_b + j - 1);
				swap1(buffer_c + j, buffer_c + j - 1);
				swap1(buffer_a1 + j, buffer_a1 + j - 1);
				swap1(buffer_a2 + j, buffer_a2 + j - 1);
				swap1(index_buffer + j, index_buffer + j - 1);
			}else{
				//this is for oblivous random access attack
				swap1(buffer_TDT + j, buffer_TDT + j);
				swap1(buffer_b + j, buffer_b + j);
				swap1(buffer_c + j, buffer_c + j);
				swap1(buffer_a1 + j, buffer_a1 + j);
				swap1(buffer_a2 + j, buffer_a2 + j);
				swap1(index_buffer + j, index_buffer + j);
			}
		}
	}
#endif
}



int **cm_all;
bool cm_initiallize_flag = false;
int cm_initiallized = 0;

void freeBC(){
#ifndef PAGE_ATTACK_PROTECTION_WITHIN_PAGE
	free(buffer_b);
	free(buffer_c);
	free(buffer_a1);
	free(buffer_a2);
#else
	free(_buffer);
	free(array_b_0_tmp);
	free(array_c_0_tmp);
	free(array_a1_0_tmp);
	free(array_a2_0_tmp);
#endif

#ifdef PAGE_ATTACK_PROTECTION_RANDOM_ACESS
	free(buffer_TDT);
	free(index_buffer);
#endif

#ifdef NON_PAGE_ATTACK_PPROTECTION
	free(TDT_top_K);
	free(B_topK);
	free(C_topK);
	free(A1_topK);
	free(A2_topK);
	free(TDT_top_K_index);
	if (cm_initiallize_flag) {
		for (int i = 0; i < parties_num; i ++) {
			delete cm_all[i];
		}
	}
#endif

}

void initializeIV(int client_num)
{
	if (! iv_counter_init_flag) {
		iv_counter_init_flag = true;
		iv_counter = new int[client_num];
		for ( int i = 0; i < client_num; i ++) {
			iv_counter[i] = 0;
		}
	}
}

//load range for decompression
void load_cm( sgx_ra_context_t context,
			 char* cm, int size_in,
			 int client_num){
				 parties_num = client_num;
				 if (!cm_initiallize_flag) {
					 cm_initiallize_flag = true;
					 cm_all = new int*[client_num];
				 }
				 cm_all[cm_initiallized] = new int[(size_in - 16)/sizeof(int)];
#if defined ENCLAVE_DEBUG
				 printf( "**ENCLAVE_DEBUG** cm_size:%d\n", (size_in-16)/sizeof(int));
#endif


				 //decryption
				 sgx_status_t ret = SGX_SUCCESS;
				 sgx_ec_key_128bit_t sk_key;

				 ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
				 if(SGX_SUCCESS != ret)
					 printf("get sk key failed!!\n");

				 uint8_t aes_gcm_iv[12] = {0};

				 memcpy( aes_gcm_iv, &iv_counter[context], sizeof(int));
				 iv_counter[ context] ++;
				 //printf( "\nsecret_size:%d\n", size_in);

				 ret = sgx_rijndael128GCM_decrypt(&sk_key,
					 (uint8_t *)(cm),
					 size_in -16,
					 //(uint8_t*) secret,
					 (uint8_t*)(cm_all[cm_initiallized]),
					 &aes_gcm_iv[0],
					 12,
					 NULL,
					 0,
					 (const sgx_aes_gcm_128bit_tag_t *)
					 (cm + size_in - 16));
				 cm_initiallized += 1;
#if defined ENCLAVE_DEBUG
				 printf( "**ENCLAVE_DEBUG** Get cm!\n");
#endif

}


static __inline int findInterval(int* cm, int size, int point) {
	int index = -1;
	int left  = 0; 
	int right = size-2;
	int cnt = 0;
	while (true) {	
		int mid = (right + left)>>1;
		if (point >= cm[mid] && point < cm[mid+1]) {
			index = mid;
			break;
		}
		if (point >= cm[mid+1]) left = mid + 1;
		else right = mid;
		if (cnt++ >= size) break;
	}
	return index;
}

//@param: data received segment data followed by 16 bytes of mac
//@param: size_in includes 16 bytes of mac

void updateBC_wraper( sgx_ra_context_t context,
					 char *data, int size_in,
					 int numberofParties,
					 int topK,
					 int compression,
					 int client_i,
					 int size_after_decompression) {

						 //decryption
						 char* decrypted_temp = new char[size_in-16];
						 sgx_status_t ret = SGX_SUCCESS;
						 sgx_ec_key_128bit_t sk_key;

						 ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
						 if(SGX_SUCCESS != ret)
							 printf("get sk key failed!!\n");

						 uint8_t aes_gcm_iv[12] = {0};
						 //printf( "\nsecret_size:%d\n", size_in);

						 memcpy( aes_gcm_iv, &iv_counter[context], sizeof(int));
						 iv_counter[context] ++;
						 ret = sgx_rijndael128GCM_decrypt(&sk_key,
							 (uint8_t *)(data),
							 size_in - 16,
							 //(uint8_t*) secret,
							 (uint8_t*)(decrypted_temp),
							 &aes_gcm_iv[0],
							 12,
							 NULL,
							 0,
							 (const sgx_aes_gcm_128bit_tag_t *)
							 (data + size_in - 16));
#if defined ENCLAVE_DEBUG
						 printf("**ENCLAVE_DEBUG**decyper result: %#x \n", ret);
#endif

						 if (compression) {
							 g_buffer = new unsigned char[size_in - 16];
							 memcpy(g_buffer, decrypted_temp, size_in - 16);
							 delete[] decrypted_temp;

							 unsigned char* decompressed_temp = new unsigned char[size_after_decompression];
							 int alphabet_size = 256;
							 int RANGE_SIZE_IN_BITS = 18;
							 
							 short* lookup = (short*)malloc(((1<<RANGE_SIZE_IN_BITS) + 1) * sizeof(short));
							 
							 makeLookupTable(cm_all[client_i], alphabet_size + 2, lookup);
							 RangeMapper* rm_decode = new RangeMapper(RANGE_SIZE_IN_BITS);
							 current_byte = 0;
							 rm_decode->init();
							 int i=0;
							 while (true) {
								 int midpoint = rm_decode->getMidPoint();
								 //next is binary search algorithm that does not need having lookup array
#ifndef LOOKUP_TABLE_ENABLE
								 int index = findInterval(cm_all[client_i], alphabet_size + 2, midpoint);
								 //this is lookup table that expedites execution, either of these functions works
#else
								 int index = lookup[midpoint]; //midpoint presumed being within correct boundaries
#endif
								 if (index == alphabet_size) break; //end of data marker
								 decompressed_temp[i] = index;
								 i ++;
								 rm_decode->decodeRange(cm_all[client_i][index], cm_all[client_i][index+1]);
							 }
							 delete rm_decode;
							 delete[] g_buffer;
							 if (lookup) free(lookup);
							 //
							 ////decompression done!
							 int length = *(int*)decompressed_temp;
#if defined ENCLAVE_DEBUG
							 printf("**ENCLAVE_DEBUG**compression flag1 segment_length:%d\n", length);
#endif
							 decompressed_temp += sizeof (int);

							 if(!initiallized_flag) {
								 initiallized_flag = true;
								 initializeEnclave( length, numberofParties, topK);
							 }

							 //add
#ifdef PAGE_ATTACK_PROTECTION_WITHIN_PAGE
							 updateBC_PER_PAGE((TDT_INPUT_TYPE*)decompressed_temp, 
								 (TDT_INPUT_TYPE*)(decompressed_temp + length * sizeof(TDT_INPUT_TYPE)),
								 (TDT_INPUT_TYPE*)(decompressed_temp + 2*length * sizeof(TDT_INPUT_TYPE)),
								 (TDT_INPUT_TYPE*)(decompressed_temp + 3*length * sizeof(TDT_INPUT_TYPE)),
								 length);
#else
							 updateBC((TDT_INPUT_TYPE*)decompressed_temp, 
								 (TDT_INPUT_TYPE*)(decompressed_temp + length * sizeof(TDT_INPUT_TYPE)),
								 (TDT_INPUT_TYPE*)(decompressed_temp + 2*length * sizeof(TDT_INPUT_TYPE)),
								 (TDT_INPUT_TYPE*)(decompressed_temp + 3*length * sizeof(TDT_INPUT_TYPE)),
								 length);
#endif

							 decompressed_temp -= sizeof(int);
							 delete[] decompressed_temp;

						 }


						 else {
							 int length = *(int*)decrypted_temp;
#if defined ENCLAVE_DEBUG
							 printf("**ENCLAVE_DEBUG** with out decompression segment_length:%d\n", length);
#endif
							 decrypted_temp += sizeof(int);
							 if(!initiallized_flag) {
								 initiallized_flag = true;
								 initializeEnclave( length, numberofParties, topK);
							 }

							 //add
#ifdef PAGE_ATTACK_PROTECTION_WITHIN_PAGE
							 updateBC_PER_PAGE((TDT_INPUT_TYPE*)decrypted_temp,
								 (TDT_INPUT_TYPE*)(decrypted_temp + length * sizeof(TDT_INPUT_TYPE)),
								 (TDT_INPUT_TYPE*)(decrypted_temp + 2*length * sizeof(TDT_INPUT_TYPE)),
								 (TDT_INPUT_TYPE*)(decrypted_temp + 3*length * sizeof(TDT_INPUT_TYPE)),
								 length);
#else
							 updateBC((TDT_INPUT_TYPE*)decrypted_temp,
								 (TDT_INPUT_TYPE*)(decrypted_temp + length * sizeof(TDT_INPUT_TYPE)),
								 (TDT_INPUT_TYPE*)(decrypted_temp + 2*length * sizeof(TDT_INPUT_TYPE)),
								 (TDT_INPUT_TYPE*)(decrypted_temp + 3*length * sizeof(TDT_INPUT_TYPE)),
								 length);
#endif

							 decrypted_temp -= sizeof(int);
							 delete[] decrypted_temp;
						 }
}


#ifdef PAGE_ATTACK_PROTECTION_WITHIN_PAGE
//int L0;

void updateBC_PER_PAGE(TDT_INPUT_TYPE* array_b_0, TDT_INPUT_TYPE* array_c_0, TDT_INPUT_TYPE* array_a1_0, TDT_INPUT_TYPE* array_a2_0, int L0)
{
	

	if(updating_top_k_flag == 0){
		current_L0 = L0;		
		bzeros(array_b_0_tmp, L0);
		bzeros(array_c_0_tmp, L0);
		bzeros(array_a1_0_tmp, L0);
		bzeros(array_a2_0_tmp, L0);
		//resetIndex(index_buffer0, current_L0, index_pri);
	}

	updateSum(array_b_0, array_c_0, array_a1_0, array_a2_0, L0);

	if(updating_top_k_flag  == parties_num - 1){
		int max_num = (int)(ceil(((double)L0)/ONE_PAGE_SNP_LEN));
		TDT_INPUT_TYPE* array_b_0_tmp_0 = array_b_0_tmp;
		TDT_INPUT_TYPE* array_c_0_tmp_0 = array_c_0_tmp;
		TDT_INPUT_TYPE* array_a1_0_tmp_0 = array_a1_0_tmp;
		TDT_INPUT_TYPE* array_a2_0_tmp_0 = array_a2_0_tmp;

		updating_top_k_flag = -1;

		current_L0 = ONE_PAGE_SNP_LEN;
		while(max_num-- > 1){
			resetIndex(index_buffer0, current_L0, index_pri);
			memcpy(buffer_b0, array_b_0_tmp_0, sizeof(TDT_INPUT_TYPE) * current_L0);
			memcpy(buffer_c0, array_c_0_tmp_0, sizeof(TDT_INPUT_TYPE) * current_L0);
			memcpy(buffer_a10, array_a1_0_tmp_0, sizeof(TDT_INPUT_TYPE) * current_L0);
			memcpy(buffer_a20, array_a2_0_tmp_0, sizeof(TDT_INPUT_TYPE) * current_L0);

			calTDTs();
			updateTopK();

			array_b_0_tmp_0 += current_L0;
			array_c_0_tmp_0 += current_L0;
			array_a1_0_tmp_0 += current_L0;
			array_a2_0_tmp_0 += current_L0;

			index_pri += current_L0;
			//max_num--;
			L0 -= current_L0;
		}

		resetIndex(index_buffer0, current_L0, index_pri);
		memcpy(buffer_b0, array_b_0_tmp_0, sizeof(TDT_INPUT_TYPE) * L0);
		memcpy(buffer_c0, array_c_0_tmp_0, sizeof(TDT_INPUT_TYPE) * L0);
		memcpy(buffer_a10, array_a1_0_tmp_0, sizeof(TDT_INPUT_TYPE) * L0);
		memcpy(buffer_a20, array_a2_0_tmp_0, sizeof(TDT_INPUT_TYPE) * L0);

		current_L0 = L0;
		calTDTs();
		updateTopK();
		index_pri += L0;
		
	}
	updating_top_k_flag++;

}
#endif


//@param size_out = topK*(sizeof(TDT_OUTPUT_TYPE) + sizeof(TDT_OUTPUT_INDEX_TYPE) + 4*sizeof(TDT_INPUT_TYPE)) + 16bytes of mac
void result_encryption(char *result, int size_out, 
					   sgx_ra_context_t *context,
					   int size_context,
					   int numberofParties,
					   int topK) {

						   //initiallize TDT result buffer
						   //for topK(index||TDT||B_count||C_count||A1_count||A2_count)
						   char *TDTs = new char[ topK * (sizeof(TDT_OUTPUT_TYPE) + sizeof(TDT_OUTPUT_INDEX_TYPE) + 4 * sizeof(TDT_INPUT_TYPE))];
						   sgx_status_t ret = SGX_SUCCESS;
						   sgx_ec_key_128bit_t sk_key;
						   for (int i=0; i<numberofParties; i++)
						   {
							   ret = sgx_ra_get_keys(context[i], SGX_RA_KEY_SK, &sk_key);
							   if(SGX_SUCCESS != ret)
							   {
								   break;
							   }

							   uint8_t aes_gcm_iv[12] = {0};
							   //printf( "\nsecret_size:%d\n", secret_size);
							   memcpy( aes_gcm_iv, &iv_counter[context[i]], sizeof(int));
							   iv_counter[ context[i]] ++;


#ifdef PAGE_ATTACK_PROTECTION
							   for(int k = 0; k < topK; k++ ){

								   memcpy( TDTs + k * (sizeof(TDT_OUTPUT_TYPE) + sizeof(TDT_OUTPUT_INDEX_TYPE) + 4 * sizeof(TDT_INPUT_TYPE)), index_buffer + k, sizeof(TDT_OUTPUT_INDEX_TYPE));
								   memcpy( TDTs + sizeof(TDT_OUTPUT_INDEX_TYPE)
									   + k * (sizeof(TDT_OUTPUT_TYPE) + sizeof(TDT_OUTPUT_INDEX_TYPE) + 4 * sizeof(TDT_INPUT_TYPE)), buffer_TDT + k, sizeof(TDT_OUTPUT_TYPE));
								   memcpy( TDTs + sizeof(TDT_OUTPUT_INDEX_TYPE) + sizeof(TDT_OUTPUT_TYPE)
									   + k * (sizeof(TDT_OUTPUT_TYPE) + sizeof(TDT_OUTPUT_INDEX_TYPE) + 4 * sizeof(TDT_INPUT_TYPE)), buffer_b + k, sizeof(TDT_INPUT_TYPE));
								   memcpy( TDTs + sizeof(TDT_OUTPUT_INDEX_TYPE) + sizeof(TDT_OUTPUT_TYPE) + sizeof(TDT_INPUT_TYPE)
									   + k * (sizeof(TDT_OUTPUT_TYPE) + sizeof(TDT_OUTPUT_INDEX_TYPE) + 4 * sizeof(TDT_INPUT_TYPE)), buffer_c + k, sizeof(TDT_INPUT_TYPE));
								   memcpy( TDTs + sizeof(TDT_OUTPUT_INDEX_TYPE) + sizeof(TDT_OUTPUT_TYPE) + 2*sizeof(TDT_INPUT_TYPE)
									   + k * (sizeof(TDT_OUTPUT_TYPE) + sizeof(TDT_OUTPUT_INDEX_TYPE) + 4 * sizeof(TDT_INPUT_TYPE)), buffer_a1 + k, sizeof(TDT_INPUT_TYPE));
								   memcpy( TDTs + sizeof(TDT_OUTPUT_INDEX_TYPE) + sizeof(TDT_OUTPUT_TYPE) + 3*sizeof(TDT_INPUT_TYPE)
									   + k * (sizeof(TDT_OUTPUT_TYPE) + sizeof(TDT_OUTPUT_INDEX_TYPE) + 4 * sizeof(TDT_INPUT_TYPE)), buffer_a2 + k, sizeof(TDT_INPUT_TYPE));

							   }
#endif

#ifdef NON_PAGE_ATTACK_PPROTECTION
							   for(int k = 0; k < topK; k++ ){

								   memcpy( TDTs + k * (sizeof(TDT_OUTPUT_TYPE) + sizeof(TDT_OUTPUT_INDEX_TYPE) + 4 * sizeof(TDT_INPUT_TYPE)), &TDT_top_K_index[k], sizeof(TDT_OUTPUT_INDEX_TYPE));
								   memcpy( TDTs + sizeof(TDT_OUTPUT_INDEX_TYPE)
									   + k * (sizeof(TDT_OUTPUT_TYPE) + sizeof(TDT_OUTPUT_INDEX_TYPE) + 4 * sizeof(TDT_INPUT_TYPE)), &TDT_top_K[k], sizeof(TDT_OUTPUT_TYPE));
								   memcpy( TDTs + sizeof(TDT_OUTPUT_INDEX_TYPE) + sizeof(TDT_OUTPUT_TYPE)
									   + k * (sizeof(TDT_OUTPUT_TYPE) + sizeof(TDT_OUTPUT_INDEX_TYPE) + 4 * sizeof(TDT_INPUT_TYPE)), &B_topK[k], sizeof(TDT_INPUT_TYPE));
								   memcpy( TDTs + sizeof(TDT_OUTPUT_INDEX_TYPE) + sizeof(TDT_OUTPUT_TYPE) + sizeof(TDT_INPUT_TYPE)
									   + k * (sizeof(TDT_OUTPUT_TYPE) + sizeof(TDT_OUTPUT_INDEX_TYPE) + 4 * sizeof(TDT_INPUT_TYPE)), &C_topK[k], sizeof(TDT_INPUT_TYPE));
								   memcpy( TDTs + sizeof(TDT_OUTPUT_INDEX_TYPE) + sizeof(TDT_OUTPUT_TYPE) + 2*sizeof(TDT_INPUT_TYPE)
									   + k * (sizeof(TDT_OUTPUT_TYPE) + sizeof(TDT_OUTPUT_INDEX_TYPE) + 4 * sizeof(TDT_INPUT_TYPE)), &A1_topK[k], sizeof(TDT_INPUT_TYPE));
								   memcpy( TDTs + sizeof(TDT_OUTPUT_INDEX_TYPE) + sizeof(TDT_OUTPUT_TYPE) + 3*sizeof(TDT_INPUT_TYPE)
									   + k * (sizeof(TDT_OUTPUT_TYPE) + sizeof(TDT_OUTPUT_INDEX_TYPE) + 4 * sizeof(TDT_INPUT_TYPE)), &A2_topK[k], sizeof(TDT_INPUT_TYPE));

							   }
#endif


							   //memcpy( aes_gcm_iv, iv_counter[i], sizeof(int));

							   ret = sgx_rijndael128GCM_encrypt(&sk_key,
								   (uint8_t *)TDTs,   //input plain text
								   size_out/numberofParties - 16,
								   (uint8_t *)(result+i*size_out/numberofParties),   //encrypted text
								   &aes_gcm_iv[0],
								   12,
								   NULL,
								   0,
								   (sgx_aes_gcm_128bit_tag_t *)
								   (result+ size_out/numberofParties + i*size_out/numberofParties - 16));
						   }
						   delete[] TDTs;
						   //printf( "enclave compute done\n");

}
