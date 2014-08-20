#include "main.h"
#include <string>

#include "../src/int_utils.h"

class Str_to_integral_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Str_to_integral_test );
        CPPUNIT_TEST( testConstructor );
        CPPUNIT_TEST_EXCEPTION(outofnegbounds, std::out_of_range);
        CPPUNIT_TEST_EXCEPTION(outofposbounds, std::out_of_range);
        CPPUNIT_TEST( test_stoll );
        CPPUNIT_TEST( test_stoull );
        CPPUNIT_TEST_SUITE_END();
        public:
        void setUp() {}
        void tearDown() {}
        void testConstructor() {
                CPPUNIT_ASSERT_EQUAL(0, str_to_integral<int>("0"));
                CPPUNIT_ASSERT_EQUAL(1, str_to_integral<int>("1"));
                CPPUNIT_ASSERT_EQUAL(-1, str_to_integral<int>("-1"));
                CPPUNIT_ASSERT_EQUAL(static_cast<unsigned int>(9001), str_to_integral<unsigned int>("9001"));
        }

        void outofnegbounds() {
                str_to_integral<unsigned int>("-1");
        }

        void outofposbounds() {
                str_to_integral<uint8_t>("256");
        }

        void test_stoll() {
                CPPUNIT_ASSERT_EQUAL(static_cast<long long int>(123), fallback::std::stoll("123"));
                CPPUNIT_ASSERT_EQUAL(static_cast<long long int>(-123), fallback::std::stoll("-123"));
                CPPUNIT_ASSERT_EQUAL(static_cast<long long int>(0), fallback::std::stoll("0"));
                CPPUNIT_ASSERT_THROW(fallback::std::stoll("1234567890123456789123456789"), std::out_of_range);
                CPPUNIT_ASSERT_THROW(fallback::std::stoll("-1234567890123456789123456789"), std::out_of_range);

                CPPUNIT_ASSERT_EQUAL(static_cast<long long int>(0), fallback::std::stoll("0", 16));
                CPPUNIT_ASSERT_EQUAL(static_cast<long long int>(10), fallback::std::stoll("a", 16));
                CPPUNIT_ASSERT_EQUAL(static_cast<long long int>(15), fallback::std::stoll("F", 16));
        }

        void test_stoull() {
                CPPUNIT_ASSERT_EQUAL(static_cast<unsigned long long int>(123), fallback::std::stoull("123"));
                CPPUNIT_ASSERT_EQUAL(static_cast<unsigned long long int>(0), fallback::std::stoull("0"));
                CPPUNIT_ASSERT_THROW(fallback::std::stoull("-123"), std::out_of_range);
                CPPUNIT_ASSERT_THROW(fallback::std::stoull("12345678901234567890123456789"), std::out_of_range);

                CPPUNIT_ASSERT_EQUAL(static_cast<unsigned long long int>(0), fallback::std::stoull("0", 16));
                CPPUNIT_ASSERT_EQUAL(static_cast<unsigned long long int>(10), fallback::std::stoull("a", 16));
                CPPUNIT_ASSERT_EQUAL(static_cast<unsigned long long int>(15), fallback::std::stoull("F", 16));
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Str_to_integral_test );

