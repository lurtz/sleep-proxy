#include "split.h"
#include <sstream>

std::vector<std::string> split(const std::string& string, const char delim) {
        std::istringstream iss(string);
        std::vector<std::string> strings;
        for (std::string item; std::getline(iss, item, delim); ) {
                strings.push_back(item);
        }
        return strings;
}

