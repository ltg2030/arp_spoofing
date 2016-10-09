#include <ctype.h>
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include "MyMAC.h"

using namespace std;

MyMAC::MyMAC()
{
    for(int i=0;i<ETHER_ADDR_LEN;i++)
        this->MACArray[i]=0;
}

MyMAC::MyMAC(uint8_t *buf)
{
    for(int i=0;i<ETHER_ADDR_LEN;i++)
        this->MACArray[i]=*(buf+i);
}

MyMAC::MyMAC(string &input)
{
	for(int i=0;i<ETHER_ADDR_LEN;i++)
		this->MACArray[i] = (uint8_t) strtoul(input.substr(3*i, 2).c_str(), NULL, 16);
}

void MyMAC::getMAC(string &output)
{
	char tmp[100];
	sprintf(tmp, "%02X:%02X:%02X:%02X:%02X:%02X"
		,this->MACArray[0],this->MACArray[1],this->MACArray[2]
		,this->MACArray[3],this->MACArray[4],this->MACArray[5]);

	string tmp_string = tmp;
	output = tmp_string;
}

void MyMAC::operator=(const MyMAC& B)
{
	for(int i=0;i<ETHER_ADDR_LEN;i++)
		this->MACArray[i] = B.MACArray[i];
}

void MyMAC::print()
{
	printf("%02X:%02X:%02X:%02X:%02X:%02X"
		,this->MACArray[0],this->MACArray[1],this->MACArray[2]
		,this->MACArray[3],this->MACArray[4],this->MACArray[5]);
}
