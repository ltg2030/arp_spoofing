#ifndef MyIPV4_

#define MyIPV4_

#include <stdint.h>
#include <string>

using namespace std;

#define IPV4_ADDR_LEN 0x4

class MyIPV4{
private:
	uint8_t  IPV4Array[IPV4_ADDR_LEN];
public:
	MyIPV4();
	MyIPV4(uint8_t*);
	MyIPV4(string &);
	void getIP(string &output);
	void operator=(const MyIPV4& B);
    void print();
};

#endif
