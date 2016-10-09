#ifndef _MyARPSpoofing

#define _MyARPSpoofing

#include <string>
#include <stdint.h>
#include "MyIPV4.h"
#include "MyMAC.h"

using namespace std;

class MyARPSpoofing{

private:
    int session_count;
    string sender_ip[15];
    string sender_mac[15];
    string target_ip[15];
    string target_mac[15];
    string my_ip;
    string my_mac;
    string gateway_ip;

    string get_gateway_ip();

    void set_session_count();
    void set_session_IP();

    void set_my_ip();
    void set_my_mac();

    void set_session_MAC();

    void convert_ip_to_MAC(string &, string &);
    void sendpacket(uint8_t *, int);
    void send_request_packet();
    void send_spoof_packet_to_session_number(int);

public:
    MyARPSpoofing();
    void set_arp_spoofing_attack();
    void arp_poisoning();
};

#endif
