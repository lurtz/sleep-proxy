#include "args.h"
#include "libsleep_proxy.h"
#include <future>
#include <type_traits>
#include <algorithm>
#include <csignal>
#include <thread>

/** set to false if SIGTERM or SIGINT is received */
std::atomic_bool loop{true};

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

void watch_host_signal_handler(int signal) {
        loop = false;
        signal_handler(signal);
}

void thread_main(const Args args) {
        bool wake_success = true;
        while (loop && wake_success) {
                std::cout << "thread_main " << args.hostname << std::endl;
                while (ping_ips(args.interface, args.address) && loop) {
                        std::cout << "ping" << std::endl;
                        std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }
                if (!loop) {
                        return;
                }
                try {
                        wake_success = emulate_host(args);
                }
                catch (const Duplicate_address_exception& e) {
                        std::cout << e.what() << std::endl;
                }
                catch (const std::exception& e) {
                        std::cout << "caught exception what(): " << e.what() << std::endl;
                        loop = false;
                }
                catch (...) {
                        std::cout << "Something went terribly wrong at: " << args << std::endl;
                        loop = false;
                }
        }
        std::cout << "finished watching " << args.hostname << std::endl;
}

int main(int argc, char * argv[]) {
        signal(SIGTERM, watch_host_signal_handler);
        signal(SIGINT, watch_host_signal_handler);
        std::vector<std::thread> threads;
        for (auto& args : read_commandline(argc, argv)) {
                threads.emplace_back(thread_main, std::move(args));
        }
        std::for_each(std::begin(threads), std::end(threads), [](std::thread& t) {if (t.joinable()) t.join();});
        if (threads.empty()) {
                std::cerr << "no configuration given" << std::endl;
                return 1;
        }
        return 0;
}
