#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <map>  

using namespace std; 

class Config
{
public:
	Config(void);
	~Config(void);

	void Trim(string& inout_s);  
	int Parse(char *filePath);
	string Read(string key);

private:
	map<std::string,std::string> contents;  //!< extracted keys and values
};

