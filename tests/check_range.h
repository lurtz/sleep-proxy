#pragma once

template<typename Iterator, typename End_iter>
void check_range(Iterator&& iter, End_iter&& end, const unsigned char start, const unsigned char end_pos) {
        for (unsigned char c = start; c < end_pos && iter != end; c++,iter++) {
                CPPUNIT_ASSERT_EQUAL(static_cast<uint8_t>(16*c+c), *iter);
        }
}

template<typename Iterator, typename End_iter>
void check_header(Iterator&& iter, End_iter&& end, const unsigned char start, const unsigned char end_pos) {
        check_range(iter, end, start, end_pos);
        CPPUNIT_ASSERT(iter != end);
}

