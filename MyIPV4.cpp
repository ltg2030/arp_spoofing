#include "MyIPV4.h"
#include <stdint.h>
#include <stdio.h>
#include <iostream>
#include <string>

using namespace std;

MyIPV4::MyIPV4()
{
    for(int i=0;i<IPV4_ADDR_LEN;i++)
        this->IPV4Array[i]=0;
}

MyIPV4::MyIPV4(uint8_t* buf)
{
    for(int i=0;i<IPV4_ADDR_LEN;i++)
        this->IPV4Array[i]=*(buf+i);
}

MyIPV4::MyIPV4(string &buf)
{
	int i;
	int cnt=0;
	int P=0;
	for(i=0;i<buf.length();i++)
	{
		if(buf.at(i) == '.')
		{
			this->IPV4Array[cnt++]=P;
			P=0;
		}
		else if (buf.at(i)>='0' && buf.at(i)<='9')
			P = 10*P + buf.at(i)-'0';
	}
	this->IPV4Array[cnt]=P;
}

void MyIPV4::getIP(string &output)
{
	char tmp[100];
	sprintf(tmp, "%u.%u.%u.%u"
		,this->IPV4Array[0],this->IPV4Array[1]
		,this->IPV4Array[2],this->IPV4Array[3]);

	string tmp_string = tmp;
	output = tmp_string;
}


void MyIPV4::operator=(const MyIPV4& B)
{
    for(int i=0;i<IPV4_ADDR_LEN;i++)
        this->IPV4Array[i]=B.IPV4Array[i];
}

void MyIPV4::print()
{
	printf("%u.%u.%u.%u"
		,this->IPV4Array[0],this->IPV4Array[1]
		,this->IPV4Array[2],this->IPV4Array[3]);
}
