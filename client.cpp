#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/ssl.h"

#define CERT_FILE "client-cert.pem"
#define KEY_FILE "client-key.pem"
#define USE_SSL 1

using namespace std;

/* simplified error handling, exit on error */
void error(string msg) {
    cout << msg << endl;
    exit(0);
}

/* setup connection happens here */
BIO *setup_connection(string servername) {
    BIO *bio;

    if (USE_SSL) {
        /* ssl context */
        SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
        SSL *ssl;

        /* connect with ssl */
        bio = BIO_new_ssl_connect(ctx);
        BIO_set_conn_hostname(bio, servername.c_str());
        BIO_get_ssl(bio, &ssl);
        if (!ssl) error("error finding ssl pointer");

        /* error checks */
        if (SSL_get_verify_result(ssl) != X509_V_OK)
            error("error verifying ssl connection");
        if (bio == NULL) error("error setting up connection\n");
        if (BIO_do_connect(bio) <= 0) error("error connection failed\n");
        if (BIO_do_handshake(bio) <= 0) error("error handshake failed\n");
    } else {
        /* unsecured connect */
        bio = BIO_new_connect(servername.c_str());
    }
    return bio;
}

/* wrap send to use string */
void send(BIO *bio, string msg) {
    if (BIO_write(bio, msg.c_str(), msg.length()) <= 0)
        error("Error writing message\n");
}

/* wrap receive to use string */
string receive(BIO *bio) {
    char buffer[1024];
    memset(buffer, 0, 1024);
    if (BIO_read(bio, buffer, 1023) < 0) error("Error reading message\n");
    string msg(buffer);
    return msg;
}

/* parse list response for table representation */
/* also stores it for transfer uses */
vector<vector<string> > parser(string entry) {
    /* ignore int/uint warnings because find overflows uint */
    int pos = entry.find("\n");
    string balance = entry.substr(0, pos);
    int x = pos + 1;
    pos = entry.find("\n", x);
    string usersOnline = entry.substr(x, pos - x);
    /* find the extra newline */
    pos = entry.find("\n", pos + 1);
    vector<vector<string> > userList;
    int pos2 = entry.find('#', pos - 2);
    pos++;
    while (pos2 != string::npos) {
        vector<string> temp;
        temp.push_back(entry.substr(pos, pos2 - pos));
        pos = pos2 + 1;
        pos2 = entry.find('#', pos);
        temp.push_back(entry.substr(pos, pos2 - pos));
        pos = pos2 + 1;
        pos2 = entry.find("\n", pos);
        temp.push_back(entry.substr(pos, pos2 - pos));
        userList.push_back(temp);
        pos = pos2 + 1;
        pos2 = entry.find('#', pos);
    }
    /* also print it out */
    cout << balance << endl << usersOnline << endl;
    cout << left << setw(6) << "No:" << left << setw(25) << "Name" << left
         << setw(18) << "Address" << left << setw(8) << "Port" << endl;
    for (uint i = 0; i < userList.size(); i++) {
        cout << left << setw(6) << i << left << setw(25) << userList[i][0]
             << left << setw(18) << userList[i][1] << left << setw(8)
             << userList[i][2] << endl;
    }
    return userList;
}

/* data to be passed to worker thread */
struct workerData {
    int port;
    BIO *bio;
};

/* worker thread to handle p2p */
void *listener(void *tdata) {
    /* data receives a port and a bio */
    workerData *data = (workerData *)tdata;

    /* server bio setup */
    BIO *bio = BIO_new_accept(to_string(data->port).c_str());
    if (bio == NULL) error("error setting up connection\n");

    /* pre declared because scope issues */
    BIO *connection;
    SSL_CTX *ctx;

    if (USE_SSL) {
        /* setup ssl ctx */
        ctx = SSL_CTX_new(SSLv23_server_method());
        if (ctx == NULL) error("error loading ctx context");

        /* load certificates */
        if (!SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM))
            error("error loading certificate file");
        if (!SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM))
            error("error loading private key file");
        if (!SSL_CTX_check_private_key(ctx))
            error("error checking private key");

        /* setup BIO chain */
        connection = BIO_new_ssl(ctx, 0);
        BIO_set_accept_bios(bio, connection);
    }

    if (BIO_do_accept(bio) <= 0) error("error connection failed 2\n");

    while (true) {
        /* accept then pass to secured bio */
        if (BIO_do_accept(bio) <= 0)
            error("error listener connection failed 2\n");
        connection = BIO_pop(bio);
        string msg = receive(connection);

        /* handle exit, becasue using a select is too hard */
        if (msg == "Exit") break;

        send(data->bio, msg);
    }
    /* free up resources */
    if (USE_SSL) SSL_CTX_free(ctx);
    BIO_free(bio);
    BIO_free(connection);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    /* check for server/port */
    if (argc < 3)
        error("usage: " + string(argv[0]) + " serverHostname serverPort\n");

    /* library init */
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();

    /* main bio */
    BIO *bio = setup_connection(string(argv[1]) + ":" + string(argv[2]));

    /* create worker thread for p2p */
    int listenport = atoi(argv[3]);
    workerData *wData = new workerData{listenport, bio};
    pthread_t worker;
    if (pthread_create(&worker, NULL, listener, (void *)wData))
        error("error creating listening thread");

    /* variable declaration */
    string entry, myName, money;
    vector<vector<string> > userList;
    int login = 0;

    /* non spec compliant: confirm successful connection */
    entry = receive(bio);
    /* wait for user interaction */
    cout << entry << endl;
    while (login == 0) {
        cout << endl << "(R)egister (S)ign-in (E)xit : ";
        cin >> entry;
        switch (entry[0]) {
            case 'r':
            case 'R':
                /* handle registration */
                cout << "Please enter new account name: ";
                cin >> entry;
                cout << "Please enter starting balance: ";
                cin >> money;
                send(bio, "REGISTER#" + entry + "#" + money + "\n");
                entry = receive(bio);
                if (entry.substr(0, 3) == "100")
                    cout << "OK" << endl;
                else if (entry.substr(0, 3) == "210")
                    cout << "Fail" << endl;
                break;
            case 's':
            case 'S':
                /* handle login */
                cout << "Please enter account name: ";
                cin >> entry;
                myName = entry;
                send(bio, entry + "#" + to_string(listenport) + "\n");
                entry = receive(bio);
                if (entry.find("230 ") != string::npos ||
                    entry.find("220 ") != string::npos)
                    cout << entry << endl << "Login Failed" << endl;
                else {
                    login = 1;
                    userList = parser(entry);
                }
                break;
            case 'e':
            case 'E':
                /* handle program exit */
                login = -1;
                break;
            default:
                break;
        }
    }

    /* handle transactions while logged in */
    while (login == 1) {
        cout << endl << "(L)ist (T)ransfer (E)xit : ";
        cin >> entry;
        string p2pserver;
        switch (entry[0]) {
            case 'l':
            case 'L':
                /* handle list */
                send(bio, "List\n");
                entry = receive(bio);
                userList = parser(entry);
                break;
            case 't':
            case 'T': {
                /* handle p2p transact */
                cout << "Please enter target user: 0 - " << userList.size() - 1
                     << ": ";
                int t1, t2;
                cin >> t1;
                cout << "Please enter transaction amount: ";
                cin >> t2;

                /* create new connection to peer and close */
                BIO *p2pbio = setup_connection(userList.at(t1).at(1) + ":" +
                                               userList.at(t1).at(2));
                send(p2pbio, myName + "#" + to_string(t2) + "#" +
                                 userList.at(t1).at(0) + "\n");
                BIO_free(p2pbio);
                break;
            }
            case 'e':
            case 'E':
                /* handle program exit */
                login = -1;
                break;
            default:
                break;
        }
    }

    /* cleanup */
    send(bio, "Exit\n");
    entry = receive(bio);
    cout << entry << endl;

    /* message to listener thread to exit */
    BIO *sbio = setup_connection("localhost:" + string(argv[3]));
    send(sbio, "Exit");

    /* cleanup resources */
    pthread_join(worker, NULL);
    pthread_exit(NULL);
    BIO_free(bio);
    BIO_free(sbio);
    return 0;
}
