#pragma once

#include <string>
#include <sstream>
#include <vector>

template<typename T>
std::string to_string(T&& t) {
        std::stringstream ss;
        ss << t;
        return ss.str();
}

bool contains_only_valid_characters(const std::string& input, const std::string& valid_chars);

std::string test_characters(const std::string& input, const std::string& valid_chars, std::string error_message);

std::vector<const char *> get_c_string_array(std::vector<std::string>& strings);

