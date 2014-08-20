#include "main.h"

#include "../src/scope_guard.h"

class Scope_guard_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Scope_guard_test );
        CPPUNIT_TEST( test_scope_guard );
        CPPUNIT_TEST( test_temp_ip );
        CPPUNIT_TEST( test_block_rst );
        CPPUNIT_TEST( test_open_port );
        CPPUNIT_TEST( test_reject_tp );
        CPPUNIT_TEST( test_block_icmp );
        CPPUNIT_TEST_SUITE_END();
        public:
        void setUp() {}

        void tearDown() {}

        void test_scope_guard() {
                std::mutex ints_mutex;
                std::vector<int *> ints;
                int x = 123;
                {
                        Scope_guard sg{ptr_guard(ints, ints_mutex, x)};
                        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), ints.size());
                        CPPUNIT_ASSERT_EQUAL(&x, ints.at(0));
                        CPPUNIT_ASSERT_EQUAL(x, *ints.at(0));
                        CPPUNIT_ASSERT_EQUAL(123, x);
                }
                CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), ints.size());
                CPPUNIT_ASSERT_EQUAL(123, x);
                {
                        Scope_guard sg{ptr_guard(ints, ints_mutex, x)};
                        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), ints.size());
                        CPPUNIT_ASSERT_EQUAL(&x, ints.at(0));
                        CPPUNIT_ASSERT_EQUAL(123, x);
                        sg.free();
                        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), ints.size());
                        CPPUNIT_ASSERT_EQUAL(123, x);
                        sg.free();
                        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), ints.size());
                        CPPUNIT_ASSERT_EQUAL(123, x);
                }
                CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), ints.size());
                CPPUNIT_ASSERT_EQUAL(123, x);
                {
                        Scope_guard sg{ptr_guard(ints, ints_mutex, x)};
                        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), ints.size());
                        CPPUNIT_ASSERT_EQUAL(&x, ints.at(0));
                        CPPUNIT_ASSERT_EQUAL(123, x);
                        x = 42;
                        CPPUNIT_ASSERT_EQUAL(x, *ints.at(0));
                        int y = 21;
                        Scope_guard sg2{ptr_guard(ints, ints_mutex, y)};
                        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(2), ints.size());
                        CPPUNIT_ASSERT_EQUAL(&x, ints.at(0));
                        CPPUNIT_ASSERT_EQUAL(&y, ints.at(1));
                        CPPUNIT_ASSERT_EQUAL(21, y);
                        sg.free();
                        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), ints.size());
                        CPPUNIT_ASSERT_EQUAL(&y, ints.at(0));
                }
                // TODO test take_action()
        }

        void test_temp_ip() {
                std::string ip{"10.0.0.1/16"};
                std::string iface{"eth0"};
                Temp_ip ti{iface, ip};
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip addr add " + ip + " dev " + iface), ti(Action::add));
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip addr del " + ip + " dev " + iface), ti(Action::del));

                ip = "random stuff";
                iface = "even more randomness";
                Temp_ip ti2{iface, ip};
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip addr add " + ip + " dev " + iface), ti2(Action::add));
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip addr del " + ip + " dev " + iface), ti2(Action::del));
        }

        void test_block_rst() {
                std::string ip{"10.0.0.1/16"};
                Block_rst br{ip};
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/iptables -w -I OUTPUT -s 10.0.0.1 -p tcp --tcp-flags ALL RST,ACK -j DROP"), br(Action::add));
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/iptables -w -D OUTPUT -s 10.0.0.1 -p tcp --tcp-flags ALL RST,ACK -j DROP"), br(Action::del));

                ip = "fe80::dead:beef%eth0";
                Block_rst br2{ip};
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip6tables -w -I OUTPUT -s fe80::dead:beef -p tcp --tcp-flags ALL RST,ACK -j DROP"), br2(Action::add));
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip6tables -w -D OUTPUT -s fe80::dead:beef -p tcp --tcp-flags ALL RST,ACK -j DROP"), br2(Action::del));

                Block_rst br3{"bullshit"};
                CPPUNIT_ASSERT_THROW(br3(Action::add), std::runtime_error);
                CPPUNIT_ASSERT_THROW(br3(Action::del), std::runtime_error);
        }

        void test_open_port() {
                std::string ip{"10.0.0.1/16"};
                uint16_t port{1234};
                Open_port op{ip, port};
                CPPUNIT_ASSERT_EQUAL("/sbin/iptables -w -I INPUT -d 10.0.0.1 -p tcp --syn --dport " + std::to_string(port) + " -j ACCEPT", op(Action::add));
                CPPUNIT_ASSERT_EQUAL("/sbin/iptables -w -D INPUT -d 10.0.0.1 -p tcp --syn --dport " + std::to_string(port) + " -j ACCEPT", op(Action::del));

                ip = "fe80::affe";
                port = 666;
                Open_port op2{ip, port};
                CPPUNIT_ASSERT_EQUAL("/sbin/ip6tables -w -I INPUT -d fe80::affe -p tcp --syn --dport " + std::to_string(port) + " -j ACCEPT", op2(Action::add));
                CPPUNIT_ASSERT_EQUAL("/sbin/ip6tables -w -D INPUT -d fe80::affe -p tcp --syn --dport " + std::to_string(port) + " -j ACCEPT", op2(Action::del));

                Open_port op3{"blabla", 1234};
                CPPUNIT_ASSERT_THROW(op3(Action::add), std::runtime_error);
                CPPUNIT_ASSERT_THROW(op3(Action::del), std::runtime_error);
        }

        void test_reject_tp() {
                Reject_tp rt{"10.0.0.1/16", Reject_tp::TP::UDP};
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/iptables -w -I INPUT -d 10.0.0.1 -p udp -j REJECT"), rt(Action::add));
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/iptables -w -D INPUT -d 10.0.0.1 -p udp -j REJECT"), rt(Action::del));
       ;
                Reject_tp rt2{"10.0.0.1/16", Reject_tp::TP::TCP};
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/iptables -w -I INPUT -d 10.0.0.1 -p tcp -j REJECT"), rt2(Action::add));
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/iptables -w -D INPUT -d 10.0.0.1 -p tcp -j REJECT"), rt2(Action::del));

                Reject_tp rt3{"2001::dead:affe/16", Reject_tp::TP::TCP};
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip6tables -w -I INPUT -d 2001::dead:affe -p tcp -j REJECT"), rt3(Action::add));
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip6tables -w -D INPUT -d 2001::dead:affe -p tcp -j REJECT"), rt3(Action::del));

                Reject_tp rt4{"invalid", Reject_tp::TP::TCP};
                CPPUNIT_ASSERT_THROW(rt4(Action::add), std::runtime_error);
                CPPUNIT_ASSERT_THROW(rt4(Action::del), std::runtime_error);
        }

        void test_block_icmp() {
                Block_icmp bi{"10.0.0.1/16"};
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/iptables -w -I OUTPUT -d 10.0.0.1 -p icmp --icmp-type destination-unreachable -j DROP"), bi(Action::add));
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/iptables -w -D OUTPUT -d 10.0.0.1 -p icmp --icmp-type destination-unreachable -j DROP"), bi(Action::del));

                Block_icmp bi2{"fe80::affe:affe"};
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip6tables -w -I OUTPUT -d fe80::affe:affe -p icmpv6 --icmpv6-type destination-unreachable -j DROP"), bi2(Action::add));
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip6tables -w -D OUTPUT -d fe80::affe:affe -p icmpv6 --icmpv6-type destination-unreachable -j DROP"), bi2(Action::del));

                Block_icmp bi3{"ratzfatz"};
                CPPUNIT_ASSERT_THROW(bi3(Action::add), std::runtime_error);
                CPPUNIT_ASSERT_THROW(bi3(Action::del), std::runtime_error);
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Scope_guard_test );

