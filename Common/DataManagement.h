#pragma once

#define DATA_PLINK 0
#define DATA_VCF 1


class DataManagement
{
public:
	DataManagement(void);
	~DataManagement(void);

	static DataManagement *make_data_management(int choice);

	int count_lines(char *filename);
	virtual int ReadFile(char *fileName) = 0;
	virtual int ReadFile2(char *fileName1, char *fileName2) = 0;
	virtual int ProcessResult(char *decrypted_result, int length) = 0;

	char* p_data;
	int data_size;
};

