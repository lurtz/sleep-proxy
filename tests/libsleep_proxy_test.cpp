#include "main.h"

#include "../src/libsleep_proxy.h"
#include "../src/libsleep_proxy_test_interface.h"
#include <csignal>

class Libsleep_proxy_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Libsleep_proxy_test );
        CPPUNIT_TEST( test_sigterm );
        CPPUNIT_TEST( test_sigint );
        CPPUNIT_TEST( test_ping_and_wait );
        CPPUNIT_TEST( test_duplicate_address_detection_exception );
        CPPUNIT_TEST_SUITE_END();
        public:
        void setUp() {
                reset_signaled();
        }

        void tearDown() {}

        void test_sigterm() {
                CPPUNIT_ASSERT(!is_signaled());
                setup_signals();
                CPPUNIT_ASSERT(!is_signaled());
                raise(SIGTERM);
                CPPUNIT_ASSERT(is_signaled());
        }

        void test_sigint() {
                CPPUNIT_ASSERT(!is_signaled());
                setup_signals();
                CPPUNIT_ASSERT(!is_signaled());
                raise(SIGINT);
                CPPUNIT_ASSERT(is_signaled());
        }

        void test_ping_and_wait() {
                CPPUNIT_ASSERT(ping_and_wait("lo", "127.0.0.1", 5));
                CPPUNIT_ASSERT(!ping_and_wait("lo", "127.0.0.1", 0));
                CPPUNIT_ASSERT(ping_and_wait("eth0", "127.0.0.1", 5));
                CPPUNIT_ASSERT(!ping_and_wait("eth0", "127.0.0.1", 0));
                CPPUNIT_ASSERT(ping_and_wait("lo", "::1", 5));
                CPPUNIT_ASSERT(!ping_and_wait("lo", "::1", 0));
                CPPUNIT_ASSERT(ping_and_wait("eth0", "::1", 5));
                CPPUNIT_ASSERT(!ping_and_wait("eth0", "::1", 0));

                CPPUNIT_ASSERT(!ping_and_wait("lo", "192.168.254.200", 5));
                CPPUNIT_ASSERT(!ping_and_wait("eth0", "192.168.254.200", 5));
                CPPUNIT_ASSERT(!ping_and_wait("lo", "::2", 5));
                CPPUNIT_ASSERT(!ping_and_wait("eth0", "::2", 5));
        }

        void test_duplicate_address_detection_exception() {
                bool catched = false;
                const std::string txt = "here would is txt";
                try {
                        throw Duplicate_address_exception(txt);
                }
                catch (const Duplicate_address_exception& e) {
                        catched = true;
                        CPPUNIT_ASSERT_EQUAL("one of these ips is owned by another machine: " + txt, std::string(e.what()));
                }
                CPPUNIT_ASSERT(catched);
        }

};

CPPUNIT_TEST_SUITE_REGISTRATION( Libsleep_proxy_test );

