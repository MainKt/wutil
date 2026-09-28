/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026, Muhammad Saheed <saheed@FreeBSD.org>
 */

#ifndef MOCK_SUPPLICANT_H
#define MOCK_SUPPLICANT_H

#include <sys/un.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>

#include "../wifi.h"
#include "../wpa_ctrl.h"

struct mock_supplicant_worker_state {
	atomic_bool running;

	pthread_mutex_t mutex;
	int fd;
	struct supplicant_status *status;
	struct scan_results *srs;
	struct known_networks *kns;
};

struct mock_supplicant {
	char *sock_dir;
	struct sockaddr_un sockaddr;
	struct mock_supplicant_worker_state worker_state;
	pthread_t worker;
};

struct mock_supplicant *mock_supplicant_create(void);
void mock_supplicant_destroy(struct mock_supplicant *);

bool mock_supplicant_set_known_networks(struct mock_supplicant *,
    struct known_networks const *);
bool mock_supplicant_set_scan_results(struct mock_supplicant *,
    struct scan_results const *);
bool mock_supplicant_set_status(struct mock_supplicant *,
    struct supplicant_status const *);

struct wpa_ctrl *wpa_ctrl_open_mock(struct mock_supplicant *);

#endif /* !MOCK_SUPPLICANT_H */
