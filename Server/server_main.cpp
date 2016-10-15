#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>

#include "Config.h"
#include "server_lib.h"


using namespace std;


int server (ServerContext *serverCtx)
{
	InitEnclave(serverCtx);

	//Wait for the clients to connect and attestation
	WaitForClients(serverCtx);

	ReceiveDataFromClient(serverCtx);

	ProcessandSendResults(serverCtx);

	return 0;
}


int main(int argc, char *argv[]) {
	//usage:
	//Distributed_Secure_GWAS -c <config file path>
	//Distributed_Secure_GWAS -n <number of clients> -p <port> -a <algorithm>
	//Distributed_Secure_GWAS -h
	//Distributed_Secure_GWAS -v

	//parse the arguments
	ServerContext *serverCtx = new ServerContext;;
	initServerContext(serverCtx);
	serverCtx->resultFolder = CreateResultFolder();

	for (int i = 1; i < argc; i++) 
	{
		if (argv[i][0] == '-') 
		{
			if (argv[i][1] == 'c') 
			{
				Config configSetting;
				
				if (configSetting.Parse(argv[i+1]))
				{
					serverCtx->account_count = atoi(configSetting.Read("AccountCount").c_str());
					serverCtx->client_num = atoi(configSetting.Read("ClientNum").c_str());
					serverCtx->algo = atoi(configSetting.Read("Algortihm").c_str());
					if (serverCtx->algo == 0) //TDT
					{
						serverCtx->topK = atoi(configSetting.Read("TopK").c_str());
						serverCtx->segment_length = atoi(configSetting.Read("SegmentLength").c_str());

					}
					serverCtx->port = atoi(configSetting.Read("ServerPort").c_str());
					serverCtx->compression = atoi(configSetting.Read("Compression").c_str());
					serverCtx->request_summary = atoi(configSetting.Read("RequestSummary").c_str());
					serverCtx->SSLenable = atoi(configSetting.Read("SSL").c_str());

					serverCtx->username = new char*[serverCtx->account_count];
					serverCtx->password = new char*[serverCtx->account_count];

					for (int j=0; j<serverCtx->account_count; j++)
					{
						string key_u = "Username";
						key_u += std::to_string(j);
						int length = configSetting.Read(key_u).length();
						serverCtx->username[j] = new char[length+1];
						strcpy(serverCtx->username[j], configSetting.Read(key_u).c_str());

						string key_p = "Password";
						key_p += std::to_string(j);
						length = configSetting.Read(key_p).length();
						serverCtx->password[j] = new char[length+1];
						strcpy(serverCtx->password[j], configSetting.Read(key_p).c_str());
					}
					i++;
				}
				else
				{
					printf("Config file open fail.\n");
					return -1;
				}
			}
			else if (argv[i][1] == 'n') 
			{
				serverCtx->client_num = atoi(argv[i+1]);
				i++;
			}
			else if (argv[i][1] == 'p')
			{
				serverCtx->port = atoi(argv[i+1]);
				i++;
			}
			else if (argv[i][1] == 'a')
			{
				serverCtx->algo = atoi(argv[i+1]);
				i++;
			}
			else if (argv[i][1] == 'h')
			{
				printf("usage:\n");
				printf("Distributed_Secure_GWAS -c <config file path>\n");
				printf("Distributed_Secure_GWAS -n <number of clients> -p <port> -a <algorithm>\n");
				printf("Distributed_Secure_GWAS -h\n");
				printf("Distributed_Secure_GWAS -v\n");
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

	server(serverCtx);

	return 0;
}
