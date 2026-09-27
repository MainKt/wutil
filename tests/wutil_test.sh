#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026, Muhammad Saheed <saheed@FreeBSD.org>
#

atf_test_case hello
hello_head()
{
	atf_set "descr" "Hello"
}
hello_body()
{
	atf_check true
}

atf_init_test_cases()
{
	atf_add_test_case hello
}
