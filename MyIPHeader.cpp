#include "MyIPHeader.h"

string MyIPHeader::get_src_ip()
{
    string tmp;
    this->ip_src.getIP(tmp);
    return tmp;
}
string MyIPHeader::get_dst_ip()
{
    string tmp;
    this->ip_dst.getIP(tmp);
    return tmp;
}
