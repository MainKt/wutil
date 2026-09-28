/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/pciio.h>
#include <sys/sysctl.h>

#include <net/if_dl.h>

#include <atf-c.h>
#include <ifaddrs.h>
#include <stdbool.h>
#include <unistd.h>

#include "../interface.h"

static bool in_vnet_jail(void);

ATF_TC_WITHOUT_HEAD(is_wlan_group_null_ifname);
ATF_TC_BODY(is_wlan_group_null_ifname, tc)
{
	struct ifconfig_handle *lifh = ifconfig_open();

	ATF_REQUIRE(lifh != NULL);
	ATF_CHECK(!is_wlan_group(lifh, NULL));

	ifconfig_close(lifh);
}

ATF_TC_WITHOUT_HEAD(is_wlan_group_invalid_ifname);
ATF_TC_BODY(is_wlan_group_invalid_ifname, tc)
{
	struct ifconfig_handle *lifh = ifconfig_open();

	ATF_REQUIRE(lifh != NULL);
	ATF_CHECK(!is_wlan_group(lifh, "NoSuchInterface"));

	ifconfig_close(lifh);
}

ATF_TC(is_wlan_group_not_member);
ATF_TC_HEAD(is_wlan_group_not_member, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "execenv", "jail");
	atf_tc_set_md_var(tc, "execenv.jail.params", "vnet");
}
ATF_TC_BODY(is_wlan_group_not_member, tc)
{
	struct ifconfig_handle *lifh = NULL;

	if (!in_vnet_jail())
		atf_tc_skip("needs a vnet jail, run using kyua");

	lifh = ifconfig_open();
	ATF_REQUIRE(lifh != NULL);
	ATF_CHECK(!is_wlan_group(lifh, "lo0"));

	ifconfig_close(lifh);
}

ATF_TC(is_wlan_group_wlan);
ATF_TC_HEAD(is_wlan_group_wlan, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "execenv", "jail");
	atf_tc_set_md_var(tc, "execenv.jail.params", "vnet");
}
ATF_TC_BODY(is_wlan_group_wlan, tc)
{
	struct ifgroupreq ifgr = {
		.ifgr_name = "lo0",
		.ifgr_group = "wlan",
	};
	int fd = -1;
	struct ifconfig_handle *lifh = NULL;

	if (!in_vnet_jail())
		atf_tc_skip("needs a vnet jail, run using kyua");

	fd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE(ioctl(fd, SIOCAIFGROUP, &ifgr) != -1);

	close(fd);

	lifh = ifconfig_open();
	ATF_REQUIRE(lifh != NULL);
	ATF_CHECK(is_wlan_group(lifh, "lo0"));

	ifconfig_close(lifh);
}

ATF_TC_WITHOUT_HEAD(is_ifaddr_af_inet);
ATF_TC_BODY(is_ifaddr_af_inet, tc)
{
	struct {
		struct sockaddr sa;
		bool expected;
	} cases[] = {
		{ { .sa_family = AF_INET }, true },
		{ { .sa_family = AF_INET6 }, true },
		{ { .sa_family = AF_LINK }, false },
	};
	struct ifconfig_handle *lifh = ifconfig_open();

	ATF_REQUIRE(lifh != NULL);
	for (size_t i = 0; i < nitems(cases); i++) {
		struct ifaddrs ifa = { .ifa_addr = &cases[i].sa };
		bool flag = false;

		is_ifaddr_af_inet(lifh, &ifa, &flag);
		ATF_CHECK_EQ(flag, cases[i].expected);
	}

	ifconfig_close(lifh);
}

ATF_TC_WITHOUT_HEAD(get_mac_add);
ATF_TC_BODY(get_mac_add, tc)
{
	struct {
		struct sockaddr_dl sdl;
		uint8_t expected[ETHER_ADDR_LEN];
	} cases[] = {
		{
		    {
			.sdl_family = AF_LINK,
			.sdl_alen = ETHER_ADDR_LEN,
			.sdl_data = { 0xc8, 0x5b, 0x76, 0xf0, 0x9f, 0x85 },
		    },
		    { 0xc8, 0x5b, 0x76, 0xf0, 0x9f, 0x85 },
		},
		{
		    {
			.sdl_family = AF_INET,
			.sdl_alen = ETHER_ADDR_LEN,
			.sdl_data = { 0xc8, 0x5b, 0x76, 0xf0, 0x9f, 0x85 },
		    },
		    { 0 },
		},
		{
		    {
			.sdl_family = AF_LINK,
			.sdl_alen = ETHER_ADDR_LEN - 1,
			.sdl_data = { 0xc8, 0x5b, 0x76, 0xf0, 0x9f, 0x85 },
		    },
		    { 0 },
		},
	};
	struct ifconfig_handle *lifh = ifconfig_open();

	ATF_REQUIRE(lifh != NULL);

	for (size_t i = 0; i < nitems(cases); i++) {
		struct ifaddrs ifa = { .ifa_addr = (void *)&cases[i].sdl };
		struct ether_addr ea = {};

		get_mac_addr(lifh, &ifa, &ea);

		for (size_t j = 0; j < ETHER_ADDR_LEN; j++)
			ATF_CHECK_EQ(ea.octet[j], cases[i].expected[j]);
	}

	ifconfig_close(lifh);
}

ATF_TC_WITHOUT_HEAD(get_iface_parent_errors);
ATF_TC_BODY(get_iface_parent_errors, tc)
{
	struct {
		const char *name;
		int expected;
	} cases[] = {
		{ "wlan", 1 },
		{ "em0", 1 },
		{ NULL, 1 },
		{ "wlan0x", 1 },
	};
	char buf[32];

	for (size_t i = 0; i < nitems(cases); i++) {
		int len = cases[i].name == NULL ? 0 : strlen(cases[i].name);
		int status = get_iface_parent(cases[i].name, len, buf,
		    sizeof(buf));

		ATF_CHECK_EQ(status, cases[i].expected);
	}

	ATF_CHECK_EQ(1, get_iface_parent(NULL, 4, buf, sizeof(buf)));
}

ATF_TC_WITHOUT_HEAD(get_iface_parent_wlan);
ATF_TC_BODY(get_iface_parent_wlan, tc)
{
	struct ifaddrs *ifaddrs = NULL;
	char ifname[IFNAMSIZ] = {};
	bool found = false;

	if (getifaddrs(&ifaddrs) == 0) {
		for (struct ifaddrs *ifa = ifaddrs; ifa != NULL;
		    ifa = ifa->ifa_next) {
			if (strncmp(ifa->ifa_name, "wlan", 4) == 0) {
				strlcpy(ifname, ifa->ifa_name, sizeof(ifname));
				found = true;
				break;
			}
		}
		freeifaddrs(ifaddrs);
	}

	if (!found)
		atf_tc_skip("no wlan interface on this system");

	{
		char parent[PCI_MAXNAMELEN + 1];
		int status = get_iface_parent(ifname, strlen(ifname), parent,
		    sizeof(parent));

		ATF_REQUIRE_EQ(0, status);
		ATF_CHECK(parent[0] != '\0');
	}

	{
		char shortbuf[1];
		int status = get_iface_parent(ifname, strlen(ifname), shortbuf,
		    sizeof(shortbuf));

		ATF_CHECK_EQ(1, status);
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, is_wlan_group_null_ifname);
	ATF_TP_ADD_TC(tp, is_wlan_group_invalid_ifname);
	ATF_TP_ADD_TC(tp, is_wlan_group_not_member);
	ATF_TP_ADD_TC(tp, is_wlan_group_wlan);
	ATF_TP_ADD_TC(tp, is_ifaddr_af_inet);
	ATF_TP_ADD_TC(tp, get_mac_add);
	ATF_TP_ADD_TC(tp, get_iface_parent_errors);
	ATF_TP_ADD_TC(tp, get_iface_parent_wlan);

	return (atf_no_error());
}

static bool
in_vnet_jail(void)
{
	int vnet = 0;
	size_t len = sizeof(vnet);

	if (sysctlbyname("security.jail.vnet", &vnet, &len, NULL, 0) != 0)
		return (false);

	return (vnet != 0);
}
