#pragma once

#include <sstream>
#include <string>
#include <algorithm>
#include <iterator>

template<typename Container, typename Func>
std::string join(Container c, Func fun, std::string sep) {
        typedef typename std::result_of<decltype(fun)(typename Container::value_type)>::type input_type;
        std::stringstream ss;
        std::ostream_iterator<input_type> iter(ss, sep.c_str());
        if (std::begin(c) != std::end(c)) {
                std::transform(std::begin(c), std::end(c)-1, iter, fun);
                ss << fun(*(std::end(c)-1));
        }
        return ss.str();
}

template<typename T>
T repeat(const T& s, const unsigned int count, T&& init = T()) {
        std::vector<T> range(count, s);
        return std::accumulate(std::begin(range), std::end(range), init);
}

