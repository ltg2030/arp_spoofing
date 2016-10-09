#ifndef _MyETHER
#define _MyEHER

#include "MyMAC.h"

class MyETHER
{
private:
    MyMAC ether_dhost; /* destination ethernet address */
    MyMAC ether_shost; /* source ethernet address */
    uint16_t ether_type; /* protocol */
#ifndef ETHERTYPE_PUP
#define ETHERTYPE_PUP           0x0200  /* PUP protocol */
#endif
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#endif
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP           0x0806  /* addr. resolution protocol */
#endif
#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP        0x8035  /* reverse addr. resolution protocol */
#endif
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN          0x8100  /* IEEE 802.1Q VLAN tagging */
#endif
#ifndef ETHERTYPE_EAP
#define ETHERTYPE_EAP           0x888e  /* IEEE 802.1X EAP authentication */
#endif
#ifndef ETHERTYPE_MPLS
#define ETHERTYPE_MPLS          0x8847  /* MPLS */
#endif
#ifndef ETHERTYPE_LOOPBACK
#define ETHERTYPE_LOOPBACK      0x9000  /* used to test interfaces */
#endif
public:
	MyETHER();
	MyETHER(uint8_t *);
	void setDhost(string &buf);
	void setDhostBroadCastFF();
	void setDhostBroadCast00();
	void setShost(string &buf);
	void set_ether_type(uint16_t);
	void print();
	uint16_t get_ether_type();
	string getDhost();
	string getShost();
};

#endif
