#include "MyARP.h"
#include <stdio.h>
#include <string>
#include <arpa/inet.h>

using namespace std;

MyARP::MyARP()
{
    this->ar_hrd = 0;
    this->ar_pro = 0;
    this->ar_hln = 0;
    this->ar_pln = 0;
    this->ar_op = 0;
    this->arp_sha = MyMAC();
    this->arp_spa = MyIPV4();
    this->arp_tha = MyMAC();
    this->arp_tpa = MyIPV4();
}

MyARP::MyARP(uint8_t *buf)
{
    this->ar_hrd = *(uint16_t *)(buf);
    this->ar_pro = *(uint16_t *)(buf+2);
    this->ar_hln = *(buf+4);
    this->ar_pln = *(buf+5);
    this->ar_op = *(uint16_t *)(buf+6);
    this->arp_sha = MyMAC(buf+8);
    this->arp_spa = MyIPV4(buf+14);
    this->arp_tha = MyMAC(buf+18);
    this->arp_tpa = MyIPV4(buf+24);
}

uint16_t MyARP::get_ar_hrd()
{
    return ntohs(this->ar_hrd);
}

uint16_t MyARP::get_ar_pro()
{
    return ntohs(this->ar_pro);
}

uint8_t MyARP::get_ar_hln()
{
    return this->ar_hln;
}

uint8_t MyARP::get_ar_pln()
{
    return this->ar_pln;
}

uint16_t MyARP::get_ar_op()
{
    return ntohs(this->ar_op);
}

void MyARP::get_arp_sha(string &output)
{
    this->arp_sha.getMAC(output);
}

void MyARP::get_arp_spa(string &output)
{
    this->arp_spa.getIP(output);
}

void MyARP::get_arp_tha(string &output)
{
    this->arp_tha.getMAC(output);
}

void MyARP::get_arp_tpa(string &output)
{
    this->arp_spa.getIP(output);
}

void MyARP::set_ar_hrd(uint16_t input)
{
    this->ar_hrd = htons(input);
}

void MyARP::set_ar_pro(uint16_t input)
{
    this->ar_pro = htons(input);
}

void MyARP::set_ar_hln(uint8_t input)
{
    this->ar_hln = input;
}

void MyARP::set_ar_pln(uint8_t input)
{
    this->ar_pln = input;
}

void MyARP::set_ar_op(uint16_t input)
{
    this->ar_op = htons(input);
}

void MyARP::set_arp_sha(string &buf)
{
    this->arp_sha = MyMAC(buf);
}

void MyARP::set_arp_spa(string &buf)
{
    this->arp_spa = MyIPV4(buf);
}

void MyARP::set_arp_tha(string &buf)
{
    this->arp_tha = MyMAC(buf);
}

void MyARP::set_arp_tha_broad_cast_00()
{
    string tmp = "00:00:00:00:00:00";
    this->arp_tha = MyMAC(tmp);
}

void MyARP::set_arp_tpa(string &buf)
{
    this->arp_tpa = MyIPV4(buf);
}

void MyARP::print()
{
    printf("Hardware Type : %d\n",ntohs(this->ar_hrd));
    printf("Protocol Type : %04X\n",ntohs(this->ar_pro));
    printf("Hardware Size : %d\n",this->ar_hln);
    printf("Protocol Size : %d\n",this->ar_pln);
    printf("Opcode : %d\n",ntohs(this->ar_op));

    printf("Sender Mac Address :");
    this->arp_sha.print();
    printf("\n");

    printf("Sender IP Address :");
    this->arp_spa.print();
    printf("\n");

    printf("Target Mac Address :");
    this->arp_tha.print();
    printf("\n");

    printf("Target IP Address :");
    this->arp_tpa.print();
    printf("\n");
}
