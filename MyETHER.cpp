#include <arpa/inet.h>
#include <stdio.h>
#include <string>
#include "MyETHER.h"

using namespace std;

MyETHER::MyETHER()
{
	this->ether_dhost = MyMAC();
	this->ether_shost = MyMAC();
	this->ether_type = 0;
}

MyETHER::MyETHER(uint8_t *buf)
{
	this->ether_dhost = MyMAC(buf);
	this->ether_shost = MyMAC(buf+ETHER_ADDR_LEN);
	this->ether_type = *(uint16_t *)(buf+2*ETHER_ADDR_LEN);
}

void MyETHER::setDhost(string &buf)
{
	this->ether_dhost = MyMAC(buf);
}

void MyETHER::setDhostBroadCastFF()
{
	string tmp = "ff:ff:ff:ff:ff:ff";
	this->ether_dhost = MyMAC(tmp);
}

void MyETHER::setDhostBroadCast00()
{
	string tmp = "00:00:00:00:00:00";
	this->ether_dhost = MyMAC(tmp);
}

void MyETHER::setShost(string &buf)
{
	this->ether_shost = MyMAC(buf);
}

void MyETHER::set_ether_type(uint16_t input)
{
	this->ether_type = htons(input);
}

void MyETHER::print()
{
	printf("Target MAC Address : ");
	this->ether_dhost.print();
	printf("\n");

	printf("Sender MAC Address : ");
	this->ether_shost.print();
	printf("\n");

	printf("ETHER Type : %04X\n",ntohs(this->ether_type));
}

uint16_t MyETHER::get_ether_type()
{
	return ntohs(this->ether_type);
}

string MyETHER::getDhost()
{
	string tmp;
	this->ether_dhost.getMAC(tmp);
	return tmp;
}

string MyETHER::getShost()
{
	string tmp;
	this->ether_shost.getMAC(tmp);
	return tmp;
}