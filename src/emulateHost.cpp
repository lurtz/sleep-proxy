#include "libsleep_proxy.h"
#include "log.h"

int main(int argc, char * argv[]) {
        std::vector<Args> argss(read_commandline(argc, argv));
        if (argss.empty()) {
                log_string(LOG_ERR, "no configuration given");
                return 1;
        }
        if (argss.at(0).syslog) {
                setup_log(argv[0], 0, LOG_DAEMON);
        }
        log_string(LOG_INFO, argss.at(0));
        setup_signals();
        try {
                emulate_host(argss.at(0));
        }
        catch (std::exception& e) {
                log(LOG_ERR, "what: %s", e.what());
        }
        catch (...) {
                log_string(LOG_ERR, "Something went terribly wrong");
        }
        return 0;
}

