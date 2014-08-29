#include "main.h"
#include "../src/log.h"

class Log_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Log_test );
        CPPUNIT_TEST( test_log_string );
        CPPUNIT_TEST( test_log_fmt );
        CPPUNIT_TEST_SUITE_END();

        public:
        void setUp() {
                setup_log("Log_test", LOG_CONS, LOG_USER);
        }
        void tearDown() {}
        void test_log_string() {
                log(LOG_DEBUG, "test_log_string()");
                log(LOG_NOTICE, "test_log_string()");
                log(LOG_ERR, "test_log_string()");
                log(LOG_ALERT, "test_log_string()");
        }
        void test_log_fmt() {
                syslog(LOG_DEBUG, "bla %d, %f", 42, 3.14);
                log(LOG_DEBUG, "bla %d, %f", 42, 3.14);
                log(LOG_NOTICE, "bla %d, %f", 42, 3.14);
                log(LOG_ERR, "bla %d, %f", 42, 3.14);
                log(LOG_ALERT, "bla %d, %f", 42, 3.14);
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Log_test );
