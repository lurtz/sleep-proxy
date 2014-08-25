#pragma once

#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <iterator>
#include <ostream>

/**
 * Writes the items of a vector seperated by ", " into out
 */
template<typename T, typename Alloc>
std::ostream& operator<<(std::ostream& out, std::vector<T, Alloc> v) {
        std::ostream_iterator<T> iter(out, ", ");
        if (std::begin(v) != std::end(v)) {
                std::copy(std::begin(v), std::end(v)-1, iter);
                out << static_cast<T>(*(std::end(v)-1));
        }
        return out;
}

template<typename T>
std::string to_string(T&& t) {
        std::stringstream ss;
        ss << t;
        return ss.str();
}

bool contains_only_valid_characters(const std::string& input, const std::string& valid_chars);

std::string test_characters(const std::string& input, const std::string& valid_chars, std::string error_message);

template<typename Container>
std::vector<const char *> get_c_string_array(const Container& strings) {
        static_assert(std::is_same<typename std::decay<Container>::type::value_type, std::string>::value, "container has to carry std::string");
        std::vector<const char *> ch_ptr;
        std::transform(std::begin(strings), std::end(strings), std::back_inserter(ch_ptr), [](const std::string& s){return s.c_str();});
        // null termination
        ch_ptr.push_back(nullptr);
        return ch_ptr;
}

