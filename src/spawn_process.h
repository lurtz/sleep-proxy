#pragma once

#include <type_traits>
#include <string>
#include <functional>
#include "to_string.h"

uint8_t wait_until_pid_exits(const pid_t& pid);

pid_t fork_exec_pipes(const std::vector<const char *>& command, const std::string& in, const std::string& out);

template<typename Container>
pid_t spawn(Container&& cmd, const std::string& in = "", const std::string& out = "") {
        static_assert(std::is_same<typename std::decay<Container>::type::value_type, std::string>::value, "container has to carry std::string");

        // get char * of each string
        std::vector<const char *> ch_ptr = get_c_string_array(cmd);

        return fork_exec_pipes(ch_ptr, in, out);
}

