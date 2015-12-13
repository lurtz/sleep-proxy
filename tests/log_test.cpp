// Copyright (C) 2014  Lutz Reinhardt
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#include "main.h"
#include "log.h"

class Log_test : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(Log_test);
  CPPUNIT_TEST(test_log_string);
  CPPUNIT_TEST(test_log_fmt);
  CPPUNIT_TEST_SUITE_END();

public:
  void setUp() override { setup_log("Log_test", 0, LOG_USER); }
  void tearDown() override {}
  void test_log_string() {
    log_string(LOG_DEBUG, "test_log_string()");
    log_string(LOG_NOTICE, "test_log_string()");
    log_string(LOG_ERR, "test_log_string()");
    log_string(LOG_ALERT, "test_log_string()");
  }
  void test_log_fmt() {
    syslog(LOG_DEBUG, "bla %d, %f", 42, 3.14);
    log(LOG_DEBUG, "bla %d, %f", 42, 3.14);
    log(LOG_NOTICE, "bla %d, %f", 42, 3.14);
    log(LOG_ERR, "bla %d, %f", 42, 3.14);
    log(LOG_ALERT, "bla %d, %f", 42, 3.14);
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(Log_test);
