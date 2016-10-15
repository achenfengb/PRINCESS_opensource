#include <stdio.h>
#include <iostream>
#include <fstream>

#include "Config.h"

#include "client_lib.h"

using namespace std;


int client (ClientContext *clientCtx)
{
	ConnectToServer(clientCtx);

	int result = attestation_client(clientCtx);
	if (clientCtx->updateEncalve)
	{
		return 1;
	}
	else
	{
		if (!result)
		{
			return 0;
		}
	}

	EncryptandSendData(clientCtx);

	ProcessResult(clientCtx);

	CloseConnection(clientCtx);

	return 1;
}

int main(int argc, char *argv[]) {
	//usage:
	//Distributed_Secure_GWAS_client -c <config file path>
	//Distributed_Secure_GWAS_client -s <server IP> -p <port> -f <case file path> <control file path>
	//Distributed_Secure_GWAS_client -h
	//Distributed_Secure_GWAS_client -v

	//parse the arguments

	ClientContext *clientCtx = new ClientContext;;
	InitClientContext(clientCtx);

	if (argc <= 1)
	{

		Config configSetting;
		if (configSetting.Parse("client_config.txt"))
		{
			//configSetting.Read("DataFilePath0").length()
			strcpy_s(clientCtx->server_IP, configSetting.Read("ServerIP").c_str());
			clientCtx->max_timeout = atoi( configSetting.Read("MaxAttempt").c_str());
			clientCtx->parser = atoi(configSetting.Read("Parser").c_str());
			clientCtx->port = atoi(configSetting.Read("ServerPort").c_str());
			strcpy_s(clientCtx->private_Key, configSetting.Read("PrivateKey").c_str());
			clientCtx->g_sp_priv_key = convert_private_key(clientCtx->private_Key);
			strcpy_s(clientCtx->file_path_TDT, configSetting.Read("DataFilePath0").c_str());
			strcpy_s(clientCtx->file_path_freq, configSetting.Read("DataFilePath1").c_str());
			strcpy_s(clientCtx->username, configSetting.Read("Username").c_str());
			strcpy_s(clientCtx->password, configSetting.Read("Password").c_str());
			clientCtx->updateEncalve = atoi(configSetting.Read("UpdateEnclave").c_str());
			strcpy_s(clientCtx->enclaveID, configSetting.Read("EnclaveID").c_str());
		}
		else
		{
			printf("Config file open fail.\n");
			return -1;
		}

	}
	else {
		for (int i = 1; i < argc; i++) 
		{
			if (argv[i][0] == '-') 
			{			
				if (argv[i][1] == 'c') 
				{
					Config configSetting;
					if (configSetting.Parse(argv[i+1]))
					{
						//configSetting.Read("DataFilePath0").length()
						strcpy_s(clientCtx->server_IP, configSetting.Read("ServerIP").c_str());
						clientCtx->max_timeout = atoi( configSetting.Read("MaxAttempt").c_str());
						clientCtx->parser = atoi(configSetting.Read("Parser").c_str());
						clientCtx->port = atoi(configSetting.Read("ServerPort").c_str());
						strcpy_s(clientCtx->private_Key, configSetting.Read("PrivateKey").c_str());
						clientCtx->g_sp_priv_key = convert_private_key(clientCtx->private_Key);
						strcpy_s(clientCtx->file_path_TDT, configSetting.Read("DataFilePath0").c_str());
						strcpy_s(clientCtx->file_path_freq, configSetting.Read("DataFilePath1").c_str());
						strcpy_s(clientCtx->username, configSetting.Read("Username").c_str());
						strcpy_s(clientCtx->password, configSetting.Read("Password").c_str());
						clientCtx->updateEncalve = atoi(configSetting.Read("UpdateEnclave").c_str());
						strcpy_s(clientCtx->enclaveID, configSetting.Read("EnclaveID").c_str());
						i++;
					}
					else
					{
						printf("Config file open fail.\n");
						return -1;
					}
				}
				else if (argv[i][1] == 's') 
				{
					strcpy_s(clientCtx->server_IP, argv[i+1]);
					i++;
				}
				else if (argv[i][1] == 'p')
				{
					clientCtx->port = atoi(argv[i+1]);
					i++;
				}
				else if (argv[i][1] == 'f')
				{
					strcpy_s(clientCtx->file_path_TDT, argv[i+1]);
					strcpy_s(clientCtx->file_path_freq, argv[i+2]);
					i+=2;
				}
				else if (argv[i][1] == 'h')
				{
					printf("usage:\n");
					printf("Distributed_Secure_GWAS_client -c <config file path>\n");
					printf("Distributed_Secure_GWAS_client -s <server IP> -p <port> -f <case file path> <control file path>\n");
					printf("Distributed_Secure_GWAS_client -h\n");
					printf("Distributed_Secure_GWAS_client -v\n");
					return 0;
				}
				else if (argv[i][1] == 'v')
				{
					printf("Version: v1.0\nRelease data: Feb 10th 2016\n");
					return 0;
				}
				else 
				{
					printf("Unknown option!\n");
					return -1;
				}
			} 
			else 
			{
				printf("Unknown option!\n");
				return -1;
			}

		}
	}
	
	InitClientContextAfterConfig(clientCtx);
	client(clientCtx);

	return 0;
}
