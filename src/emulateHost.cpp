#include "libsleep_proxy.h"
#include <iostream>

int main(int argc, char * argv[]) {
        std::vector<Args> argss(read_commandline(argc, argv));
        if (argss.empty()) {
                std::cerr << "no configuration given" << std::endl;
                return 1;
        }
        std::cout << argss.at(0) << std::endl;
        setup_signals();
        // if possible exceptions aren't catched the scope guards won't work
        try {
                emulate_host(argss.at(0));
        }
        catch (std::exception& e) {
                std::cout << "what: " << e.what() << std::endl;
        }
        catch (...) {
                std::cout << "Something went terribly wrong" << std::endl;
        }
        return 0;
}

