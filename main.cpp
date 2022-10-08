#include "socks5/socks5_server.h"

int main(int argc, char* argv[]) {
    Socks5Server server("0.0.0.0", 7777);
    server.loop();
    return 0;
}