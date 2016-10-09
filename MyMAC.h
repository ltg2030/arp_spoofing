#ifndef MyMAC_

#define MyMAC_

#include <stdint.h>
#include <string>

using namespace std;

#define ETHER_ADDR_LEN 0x6

class MyMAC{
private:
	uint8_t  MACArray[ETHER_ADDR_LEN];
public:
	MyMAC();
	MyMAC(uint8_t*);
	MyMAC(string &);
	void getMAC(string &);
	void operator=(const MyMAC& B);
    void print();
};

#endif
