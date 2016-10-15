Environment Setup
---

1. Hardware. You need to have a desktop/laptop with Intel SGX support on the server side to run our server codes

2. Download and install Intel SGX SDK and PSW from https://software.intel.com/en-us/sgx-sdk

3. Install Microsoft Visual Studio 2012 Professional Edition

4. Install Intel Parallel Studio XE 2016

5. Build both the server and client programs. For the difference among debug, prerelease and release, please read https://software.intel.com/en-us/blogs/2016/01/07/intel-sgx-debug-production-prelease-whats-the-difference


Compile and Link Steps
---
1. In Thirdparty/cryptopp562, compile the library for both debug or release version

2. Open Distributed_Secure_GWAS.sln and compile the solution for debug or release version.
    
3. Copy the necessary DLLs (cryptopp.dll, pthreadVC2.dll, sample_libcrypto.dll) into the binary folder

    3.1 client.exe depends on cryptopp.dll and sample_libcrypto.dll
    
    3.2 server.exe depends on pthreadVC2.dll and TDT_enclave.signed.dll
    
4. Prepare the SSL certificates https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs (enclave_server.cert.pem & enclave_server.key.pem for server and ca-chain.cert.pem for client) and put them into the binary folder

    4.1 client.exe depends on ca-chain.cert.pem
    
    4.2 server.exe depends on enclave_server.cert.pem and enclave_server.key.pem
    
Execution
---

1. Edit the config files for the server and client (sample config files are in the Config folder)

    1.1 For client_config.txt:
    
        ServerIP: The IP address where the server is hosted. Set to 127.0.0.1 if on local machine.
        
        ServerPort: The port of the server, set it to be the same as the port number used in server_config.txt
        
        MaxAttempt: Maximum number of attempts to connect to server.
        
        Username&Password: Login information for user, set it to be one of the accounts in server_config.txt
        
        UpdateEnclave: Set to 1 when enclave project is recompiled and .signed.dll is regenerated.
        
        EnclaveID: Use this to test if the enclave running on the server is as expected.
        
        PrivateKey: Secret information corresponding to the public key set in TDT enclave
        
        Parser: Please set to 0.
        
        DataFileCount: Please set to 2.
        
        DataFilePath0: The path to the tdt file.
        
        DataFilePath1: The path to the freq file.
        
    1.2 For server_config.txt:
    
        ServerPort: The port that server is listening
        
        Algorithm: Please set to 0.
        
        TopK: Output the top K largest TDT results.
        
        SegmentLength: The length of a segment of the whole SNP data in terms of the number of SNPs.
        
        Compression: If or not to turn on compression. Set it to 1 for compression, set it to 0 for non-compression.
        
        RequestSummary: Please set to 0.
        
        ClientNum: The number of clients that the server expects to wait to connect.
        
        SSL: If or not to turn on SSL. Set it to 1 for SSL, set it to 0 for non-SSL (plain socket).
        
        AccountCount: The number of accounts that the server will use.

2. Before deployment, set UpdateEnclave to be 1 in client_config.txt and run both server and client to get the EnclaveID

Run the server program as: 
```
>>server.exe -c ..\Config\server_config.txt
```

Run the client program as: 
```
>>client.exe -c ..\Config\client_config.txt
```

Contact
---
*f4chen@ucsd.edu*
