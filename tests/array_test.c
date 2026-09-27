/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <atf-c.h>

#include "../array.h"

ARRAY(array, int);
ARRAY_APPEND_STATIC(array)

ATF_TC_WITHOUT_HEAD(ops);
ATF_TC_BODY(ops, tc)
{
	struct array a = ARRAY_INITIALIZER(array);
	size_t items_to_add = 1000;

	ATF_REQUIRE_EQ(a.cap, 0);
	ATF_REQUIRE_EQ(a.len, 0);

	for (size_t i = 0; i < items_to_add; i++)
		ATF_REQUIRE(ARRAY_APPEND(array, &a, i + 1));

	for (size_t i = 0; i < items_to_add; i++)
		ATF_REQUIRE_EQ(a.items[i], i + 1);

	ARRAY_FREE(&a);

	ATF_REQUIRE_EQ(a.cap, 0);
	ATF_REQUIRE_EQ(a.len, 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, ops);

	return (atf_no_error());
}
