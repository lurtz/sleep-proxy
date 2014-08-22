#pragma once

#include <string>
#include <sstream>
#include <vector>
#include <algorithm>

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

