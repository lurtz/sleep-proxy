#include "int_utils.h"
#include <errno.h>
#include <cstdlib>
#include "to_string.h"

namespace fallback {
namespace std {
const ::std::string numbers{"-0123456789abcdefABCDEF"};

long long int stoll(const ::std::string& s, const int base) {
        if (s.size() == 0 || !contains_only_valid_characters(s, numbers)) {
                throw ::std::invalid_argument("strtoll(): cannot convert string: " + s);
        }
        auto errno_save = errno;
        errno = 0;
        auto ret_val = strtoll(s.c_str(), nullptr, base);
        switch (errno) {
                case 0: break;
                case ERANGE:
                        throw ::std::out_of_range("strtoll() failed to convert:" + s);
                        break;
                default:
                        throw ::std::invalid_argument("strtoll() failed to convert: " + s);
                        break;
        }
        errno = errno_save;
        return ret_val;
}

unsigned long long int stoull(const ::std::string& s, const int base) {
        if (s.size() == 0 || !contains_only_valid_characters(s, numbers)) {
                throw ::std::invalid_argument("strtoull(): cannot convert string: " + s);
        }
        auto errno_save = errno;
        errno = 0;
        auto ret_val = strtoull(s.c_str(), nullptr, base);
        if (s.at(0) == '-') {
                errno = ERANGE;
        }
        switch (errno) {
                case 0: break;
                case ERANGE:
                        throw ::std::out_of_range("strtoull() failed to convert:" + s);
                        break;
                default:
                        throw ::std::invalid_argument("strtoull() failed to convert: " + s);
                        break;
        }
        errno = errno_save;
        return ret_val;
}
}
}
