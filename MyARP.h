#ifndef MyARP_

#define MyARP_

#include <stdint.h>
#include <string>
#include "MyMAC.h"
#include "MyIPV4.h"

using namespace std;

class MyARP
{
public:
    uint16_t ar_hrd;         /* format of hardware address */
#define ARPHRD_NETROM   0   /* from KA9Q: NET/ROM pseudo */
#define ARPHRD_ETHER    1   /* Ethernet 10Mbps */
#define ARPHRD_EETHER   2   /* Experimental Ethernet */
#define ARPHRD_AX25     3   /* AX.25 Level 2 */
#define ARPHRD_PRONET   4   /* PROnet token ring */
#define ARPHRD_CHAOS    5   /* Chaosnet */
#define ARPHRD_IEEE802  6   /* IEEE 802.2 Ethernet/TR/TB */
#define ARPHRD_ARCNET   7   /* ARCnet */
#define ARPHRD_APPLETLK 8   /* APPLEtalk */
#define ARPHRD_LANSTAR  9   /* Lanstar */
#define ARPHRD_DLCI     15  /* Frame Relay DLCI */
#define ARPHRD_ATM      19  /* ATM */
#define ARPHRD_METRICOM 23  /* Metricom STRIP (new IANA id) */
#define ARPHRD_IPSEC    31  /* IPsec tunnel */
    uint16_t ar_pro;         /* format of protocol address */
    uint8_t  ar_hln;         /* length of hardware address */
    uint8_t  ar_pln;         /* length of protocol addres */
    uint16_t ar_op;          /* operation type */
#define ARPOP_REQUEST    1  /* req to resolve address */
#define ARPOP_REPLY      2  /* resp to previous request */
#define ARPOP_REVREQUEST 3  /* req protocol address given hardware */
#define ARPOP_REVREPLY   4  /* resp giving protocol address */
#define ARPOP_INVREQUEST 8  /* req to identify peer */
#define ARPOP_INVREPLY   9  /* resp identifying peer */
    /* address information allocated dynamically */
    MyMAC arp_sha;   /* sender hardware address */
    MyIPV4 arp_spa;  /* sender protocol address */
    MyMAC arp_tha;   /* target hardware address */
    MyIPV4 arp_tpa;  /* target protocol address */
public:
    MyARP();
    MyARP(uint8_t *);
    uint16_t get_ar_hrd();
    uint16_t get_ar_pro();
    uint8_t get_ar_hln();
    uint8_t get_ar_pln();
    uint16_t get_ar_op();
    void get_arp_sha(string &);
    void get_arp_spa(string &);
    void get_arp_tha(string &);
    void get_arp_tpa(string &);
    void set_ar_hrd(uint16_t);
    void set_ar_pro(uint16_t);
    void set_ar_hln(uint8_t);
    void set_ar_pln(uint8_t);
    void set_ar_op(uint16_t);
    void set_arp_sha(string &);
    void set_arp_spa(string &);
    void set_arp_tha(string &);
    void set_arp_tha_broad_cast_00();
    void set_arp_tpa(string &);
    void print();
};

#endif
