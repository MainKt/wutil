/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <stdio.h>

#include "usage.h"

void
usage(FILE *fout)
{
	fprintf(fout,
	    "Usage:"
	    "\twutil {-h | subcommand [args...]}\n"
	    "\twutil [-c <wpa-ctrl-path>] known-networks\n"
	    "\twutil [-c <wpa-ctrl-path>] {known-network | forget} <ssid>\n"
	    "\twutil [-c <wpa-ctrl-path>] set\n"
	    "\t  [-p <priority>] [--autoconnect {y | n}] <ssid>\n"
	    "\twutil [-c <wpa-ctrl-path>] {scan | networks | status | disconnect}\n"
	    "\twutil [-c <wpa-ctrl-path>] connect\n"
	    "\t  [-i <eap-id>] [-p <password>] [-h] <ssid> [password]\n");
}

void
usage_tui(FILE *fout)
{
	fprintf(fout,
	    "Usage:"
	    "\twutui [-h | --help]\n"
	    "\twutui [--ctrl-interface <path> | -c <path>]\n");
}
