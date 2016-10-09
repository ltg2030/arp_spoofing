OBJECTS = MyMAC.o MyETHER.o MyIPV4.o MyIPHeader.o MyARP.o MyARPSpoofing.o main.o

all: $(OBJECTS)
	g++ -o out $(OBJECTS) -lpcap
	rm $(OBJECTS)

MyMAC.o: MyMAC.cpp MyMAC.h
	g++ -c MyMAC.cpp

MyETHER.o: MyETHER.cpp MyETHER.h
	g++ -c MyETHER.cpp

MyIPV4.o: MyIPV4.cpp MyIPV4.h
	g++ -c MyIPV4.cpp

MyIPHeader.o: MyIPHeader.cpp MyIPHeader.h
	g++ -c MyIPHeader.cpp

MyARP.o: MyARP.cpp MyARP.h
	g++ -c MyARP.cpp

MyARPSend.o: MyARPSpoofing.cpp MyARPSpoofing.h
	g++ -c MyARPSpoofing.cpp

main.o: main.cpp
	g++ -c main.cpp

clean:
	rm out
