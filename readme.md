# Server

note: found in emails

## Compilation

The `make` command compiles the program
The resulting executable is called `server`

- Openssl must be installed and linked
- pthreads must be installed and linked
- The certificate/keys are defined in preprocessor directives
- The usage of SSL/TLS is defined in the preprocessor directive `USE_SSL`

## Usage

```
./server port

        port: port to listen on
The string "exit" while the server is running will gracefully exit the program
```

The following command generates the necessary private key and certificate file

```
openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout server-key.pem -out server-cert.pem
```

## Environment

The binary is compiled in an x86_64 environment

# Client

## Compilation

The `make` command compiles the program
The resulting executable is called `client`

- Openssl must be installed and linked
- pthreads must be installed and linked
- The certificate/keys are defined in preprocessor directives
- The usage of SSL/TLS is defined in the preprocessor directive `USE_SSL`

## Usage

```
./client serverHostname serverPort ownPort

	serverHostname: Host name of server
	serverPort: Port the server is listening on
	ownPort: Port to listen on for p2p transactions
```

The following command generates the necessary private key and certificate file

```
openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout client-key.pem -out client-cert.pem
```

## Environment

The binary is compiled in an x86_64 environment
