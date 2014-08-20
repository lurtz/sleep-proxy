#include "main.h"

#include "../src/split.h"

class Split_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Split_test );
        CPPUNIT_TEST( testConstructor );
        CPPUNIT_TEST_SUITE_END();
        public:
        void setUp() {}
        void tearDown() {}
        void testConstructor() {
                std::vector<std::string> result0{"a","b","c"};
                CPPUNIT_ASSERT(result0 == split("a,b,c", ','));
                std::vector<std::string> result1{"a,b,c"};
                CPPUNIT_ASSERT(result1 == split("a,b,c", ';'));
                std::vector<std::string> result2{};
                CPPUNIT_ASSERT(result2 == split("", ';'));
                std::vector<std::string> result3{"a","b","c","d"};
                CPPUNIT_ASSERT(result3 == split("a;b;c;d", ';'));
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Split_test );

