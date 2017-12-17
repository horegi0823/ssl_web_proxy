all:ssl.cpp
	g++ -o ssl ssl.cpp -std=c++11 -lssl -lcrypto -lpthread
