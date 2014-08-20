#include "libemulateHost.h"
#include <csignal>
#include <iostream>

int main(int argc, char * argv[]) {
        Args args(read_commandline(argc, argv).at(0));
        std::cout << args << std::endl;
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        // if possible exceptions aren't catched the scope guards won't work
        try {
                emulate_host(args);
        }
        catch (std::exception& e) {
                std::cout << "what: " << e.what() << std::endl;
        }
        return 0;
}

