all:
	# - gcc ./server_thread.cpp -o ./server_thread -g -lm -lcjson 
	- mkdir -p ./save
	- g++ ./server.cpp -o ./server -g -lm -lssl -lcrypto
	- g++ ./client.cpp -o ./client -g -lm -lssl -lcrypto
clean:
	- rm -f server client
