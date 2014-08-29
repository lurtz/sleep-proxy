#include <string>
#include "wol.h"
#include "ip_utils.h"
#include "log.h"

void print_help() {
        log_string(LOG_NOTICE, "usage: [-i iface] mac");
}

void check_arguments(const int argc, const int count) {
        if (argc < count) {
                print_help();
                exit(1);
        }
}

int main(int argc, char * argv[]) {
        int count = 2;
        unsigned int mac_pos = 1;
        check_arguments(argc, count);
        if (std::string("-i") == argv[1]) {
                count+=2;
                mac_pos += 2;
        }
        check_arguments(argc, count);
        std::string mac = validate_mac(argv[mac_pos]);
        if (std::string("-i") != argv[1]) {
                wol_udp(mac);
        } else {
                std::string iface = validate_iface(argv[2]);
                if (iface.size() > 13) {
                        log_string(LOG_NOTICE, "maximum of 13 characters allowed for ethernet name");
                        return 1;
                }

                wol_ethernet(iface, mac);
        }
        return 0;
}

