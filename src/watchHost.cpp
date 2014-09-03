#include "args.h"
#include "libsleep_proxy.h"
#include "log.h"
#include <future>
#include <type_traits>
#include <algorithm>
#include <csignal>
#include <thread>

/** with std::async this code is not able to build on openwrt. this is a
 * replacement */
struct Pseudo_future {
        const std::string iface_;
        const std::string ip_;
        const unsigned int tries_;
        std::thread thread;
        bool result;

        Pseudo_future(const std::string iface, const std::string ip, const unsigned int tries) : iface_(std::move(iface)), ip_(std::move(ip)), tries_(std::move(tries)), thread([&](){result = ping_and_wait(iface_, ip_, tries_);}) {
        }

        Pseudo_future(Pseudo_future&& pf) = default;

        ~Pseudo_future() {
                get();
        }

        bool get() {
                if (thread.joinable()) {
                        thread.join();
                }
                return result;
        }
};

template<typename Container>
bool ping_ips(const std::string& iface, const Container& ips) {
        std::vector<Pseudo_future> futures;
        for (const auto& ip : ips) {
                futures.emplace_back(iface, ip, 1);
        }
        return std::any_of(std::begin(futures), std::end(futures), [](Pseudo_future& f){ return f.get(); });
}

void thread_main(const Args args) {
        bool wake_success = true;
        while (!is_signaled() && wake_success) {
                log_string(LOG_INFO, "ping " + args.hostname);
                while (ping_ips(args.interface, args.address) && !is_signaled()) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }
                if (is_signaled()) {
                        return;
                }
                try {
                        wake_success = emulate_host(args);
                }
                catch (const Duplicate_address_exception& e) {
                        log_string(LOG_NOTICE,  e.what());
                }
                catch (const std::exception& e) {
                        log(LOG_ERR, "caught exception what(): %s", e.what());
                        raise(SIGTERM);
                }
                catch (...) {
                        log_string(LOG_ERR, "Something went terribly wrong at: " + to_string(args));
                        raise(SIGTERM);
                }
        }
        log_string(LOG_INFO, "finished watching " + args.hostname);
}

int main(int argc, char * argv[]) {
        setup_signals();
        auto argss = read_commandline(argc, argv);
        if (argss.empty()) {
                log_string(LOG_ERR, "no configuration given");
                return 1;
        }
        if (argss.at(0).syslog) {
                setup_log(argv[0], 0, LOG_DAEMON);
        }
        std::vector<std::thread> threads;
        for (auto& args : argss) {
                threads.emplace_back(thread_main, std::move(args));
        }
        std::for_each(std::begin(threads), std::end(threads), [](std::thread& t) {if (t.joinable()) t.join();});
        return 0;
}
