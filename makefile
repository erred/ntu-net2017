all: client server

client: client.cpp
	g++ client.cpp -lpthread -lssl -lcrypto -o client

server: server.cpp
	g++ server.cpp -lpthread -lssl -lcrypto -o server
