#include "spawn_process.h"
#include <sys/wait.h>
#include <unistd.h>
#include <stdexcept>
#include <fcntl.h>
#include <cstring>
#include <cstdlib>
#include <errno.h>
#include <tuple>

uint8_t wait_until_pid_exits(const pid_t& pid) {
        int status;
        do {
                pid_t wpid = waitpid(pid, &status, WUNTRACED | WCONTINUED);
                if (wpid == -1) {
                        throw std::runtime_error(std::string("waitpid() failed: ") + strerror(errno));
                }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
        return WEXITSTATUS(status);
}

struct Pipe {
        const int fd;
        bool closed = false;
        Pipe(const int fdd) : fd(fdd) {
                if (fdd < 0) {
                        throw std::runtime_error(std::string("file descriptor is negative: ") + strerror(errno));
                }
        }
        Pipe(Pipe&& rhs) : fd(rhs.fd), closed(rhs.closed) {
                rhs.closed = true;
        }
        Pipe(const Pipe&) = delete;
        ~Pipe() {
                close();
        }
        Pipe& operator=(const Pipe&) = delete;
        void close() {
                if (!closed) {
                        if (::close(fd) == -1) {
                                throw std::runtime_error(std::string("pipe close() failed: ") + strerror(errno));
                        }
                }
                closed = true;
        }
};

std::tuple<Pipe, Pipe> get_self_pipes() {
        int pipefds[2];
        if (pipe(pipefds)) {
                throw std::runtime_error(std::string("pipe() failed: ") + strerror(errno));
        }
        Pipe p0{pipefds[0]}, p1{pipefds[1]};
        if (fcntl(p1.fd, F_SETFD, fcntl(p1.fd, F_GETFD) | FD_CLOEXEC)) {
                throw std::runtime_error(std::string("fcntl() failed: ") + strerror(errno));
        }

        return std::make_tuple(std::move(p0), std::move(p1));
}

pid_t fork_exec_pipes(const std::vector<const char *>& command) {
        std::tuple<Pipe, Pipe> pipes = get_self_pipes();

        pid_t child = fork();
        switch (child) {
                case -1:
                        throw std::runtime_error(std::string("fork() failed with error: ") + strerror(errno));
                case 0:
                        std::get<0>(pipes).close();
                        execv(command.at(0), const_cast<char **>(command.data()));
                        write(std::get<1>(pipes).fd, &errno, sizeof(int));
                        _exit(0);
                default: {
                        std::get<1>(pipes).close();
                        ssize_t count;
                        int err;
                        while ((count = read(std::get<0>(pipes).fd, &err, sizeof(err))) == -1 && (errno == EAGAIN || errno == EINTR));
                        std::get<0>(pipes).close();
                        if (count) {
                            // something bad happend in the child process
                            throw std::runtime_error(std::string("execv() failed: ") + strerror(err));
                        }
                     }
        }
        return child;
}

