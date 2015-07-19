#include "packet_test_utils.h"
#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/extensions/HelperMacros.h>
#include <string.h>
#include <unistd.h>
#include "container_utils.h"
#include "int_utils.h"

void check_range(const long long int val, const long long int lower,
                 const long long int upper) {
  if (val < lower || val >= upper) {
    throw std::out_of_range(to_string(val) + " is not in range [" +
                            to_string(lower) + "," + to_string(upper) + ")");
  }
}

/**
 * converts two hex characters into a byte value
 */
uint8_t two_hex_chars_to_byte(const char a, const char b) {
  const long long int left = fallback::std::stoll(std::string(1, a), 16);
  const long long int right = fallback::std::stoll(std::string(1, b), 16);
  check_range(left, 0, 16);
  check_range(right, 0, 16);
  return static_cast<uint8_t>(left << 4) | static_cast<uint8_t>(right);
}

std::vector<uint8_t> to_binary(const std::string &hex) {
  std::vector<uint8_t> binary;
  for (auto iter = std::begin(hex); iter < std::end(hex) - 1; iter += 2) {
    binary.push_back(two_hex_chars_to_byte(*iter, *(iter + 1)));
  }
  return binary;
}

void test_ip(const std::unique_ptr<ip> &ip, const ip::Version v,
             const std::string &src, const std::string &dst,
             const size_t header_length, const ip::Payload pl_type) {
  CPPUNIT_ASSERT(ip != nullptr);
  CPPUNIT_ASSERT_EQUAL(v, ip->version());
  CPPUNIT_ASSERT_EQUAL(parse_ip(src), ip->source());
  CPPUNIT_ASSERT_EQUAL(parse_ip(dst), ip->destination());
  CPPUNIT_ASSERT_EQUAL(static_cast<uint8_t>(pl_type), ip->payload_protocol());
  CPPUNIT_ASSERT_EQUAL(header_length, ip->header_length());
}

void test_ll(const std::unique_ptr<Link_layer> &ll, const size_t length,
             const std::string &src, const ip::Version payload_protocol,
             const std::string &info) {
  CPPUNIT_ASSERT(ll != nullptr);
  CPPUNIT_ASSERT_EQUAL(length, ll->header_length());
  CPPUNIT_ASSERT_EQUAL(src, binary_to_mac(ll->source()));
  CPPUNIT_ASSERT_EQUAL(static_cast<uint16_t>(payload_protocol),
                       ll->payload_protocol());
  CPPUNIT_ASSERT_EQUAL(info, ll->get_info());
}

bool operator==(const Link_layer &lhs, const Link_layer &rhs) {
  return lhs.header_length() == rhs.header_length() &&
         lhs.payload_protocol() == rhs.payload_protocol() &&
         lhs.get_info() == rhs.get_info();
}

bool operator==(const ip &lhs, const ip &rhs) {
  return lhs.version() == rhs.version() &&
         lhs.destination() == rhs.destination() &&
         lhs.payload_protocol() == rhs.payload_protocol() &&
         lhs.source() == rhs.source();
}

bool operator<(IP_address const &lhs, IP_address const &rhs) {
  return lhs.with_subnet() < rhs.with_subnet();
}

File_descriptor get_tmp_file(std::string const &filename) {
  std::string const path = std::string(P_tmpdir) + '/' + filename;
  std::vector<char> modifiable_string(path.size() + 1, '\0');
  std::copy(std::begin(path), std::end(path), std::begin(modifiable_string));

  int const raw_fd = mkstemp(modifiable_string.data());
  if (raw_fd == -1) {
    throw std::runtime_error(std::string("failed to create temporary file: ") +
                             strerror(errno));
  }

  return File_descriptor{raw_fd, modifiable_string.data()};
}

std::vector<std::string> get_ip_neigh_output() {
  auto const out_in = get_self_pipes(false);
  std::vector<std::string> const cmd{get_path("ip"), "neigh"};
  pid_t const pid = spawn(cmd, "/dev/null", std::get<1>(out_in));
  const uint8_t status = wait_until_pid_exits(pid);
  CPPUNIT_ASSERT_EQUAL(static_cast<uint8_t>(0), status);
  return std::get<0>(out_in).read();
}

Iface_Ips get_iface_ips(std::vector<std::string> const ip_neigh_content) {
  auto const is_ip_not_stale = [](std::string const &line) {
    return line.find("STALE") == std::string::npos &&
           line.find("DELAY") == std::string::npos &&
           line.find("PROBE") == std::string::npos &&
           line.find("FAILED") == std::string::npos;
  };

  auto const create_iface_ip = [](std::string const &line) {
    auto const token = split(line, ' ');
    return std::make_tuple(token.at(2), parse_ip(token.at(0)));
  };

  std::vector<std::string> not_stale_lines;
  std::copy_if(std::begin(ip_neigh_content), std::end(ip_neigh_content),
               std::back_inserter(not_stale_lines), is_ip_not_stale);

  Iface_Ips iface_ip(not_stale_lines.size());
  std::transform(std::begin(not_stale_lines), std::end(not_stale_lines),
                 std::begin(iface_ip), create_iface_ip);

  return iface_ip;
}

int dup_exception(int const fd) {
  auto const new_fd = dup(fd);
  if (new_fd == -1) {
    throw std::runtime_error(std::string() + strerror(errno));
  }
  return new_fd;
}

void write(File_descriptor const &fd, std::string const &text) {
  ssize_t const written_bytes = ::write(fd, text.c_str(), text.size());
  CPPUNIT_ASSERT(-1 != written_bytes);
  CPPUNIT_ASSERT_EQUAL(text.size(), static_cast<size_t>(written_bytes));
}

Fd_restore::Fd_restore(int const fd)
    : m_fd(fd), m_backup_fd(dup_exception(fd)) {}

Fd_restore::~Fd_restore() {
  try {
    duplicate_file_descriptors(m_backup_fd, m_fd);
  } catch (std::exception const &e) {
    std::cout << "Fd_restore::~Fd_restore() caught exception: " << e.what()
              << std::endl;
  }
}

Tmp_fd_remap::Tmp_fd_remap(int const from_fd, int const to_fd)
    : m_restore(to_fd) {
  duplicate_file_descriptors(from_fd, to_fd);
}

bool operator==(ether_addr const &lhs, ether_addr const &rhs) {
  return std::equal(std::begin(lhs.ether_addr_octet),
                    std::end(lhs.ether_addr_octet),
                    std::begin(rhs.ether_addr_octet));
}

std::ostream &operator<<(std::ostream &out, ether_addr const &ether_addr) {
  out << "ether_addr("
      << std::vector<uint8_t>(std::begin(ether_addr.ether_addr_octet),
                              std::end(ether_addr.ether_addr_octet)) << ")";
  return out;
}
