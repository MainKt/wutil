/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#ifndef USAGE_H
#define USAGE_H

#include <stdbool.h>
#include <stdio.h>

void usage(FILE *fout);
void usage_interface(FILE *fout, bool usage_str);
void usage_known_networks(FILE *fout, bool usage_str);
void usage_station(FILE *fout, bool usage_str);

typedef void(usage_f)(FILE *, bool);

#endif
