#include "to_string.h"
#include <stdexcept>

bool contains_only_valid_characters(const std::string& input, const std::string& valid_chars) {
        const bool b = std::all_of(std::begin(input), std::end(input), [&] (char ch) { return valid_chars.find(ch) != std::string::npos; });
        return b;
}

std::string test_characters(const std::string& input, const std::string& valid_chars, std::string error_message) {
        if (!contains_only_valid_characters(input, valid_chars)) {
                throw std::runtime_error(error_message);
        }
        return input;
}

