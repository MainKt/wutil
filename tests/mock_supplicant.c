/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "./mock_supplicant.h"

static void *mock_supplicant_worker(void *arg);

struct mock_supplicant *
mock_supplicant_create(void)
{
	struct mock_supplicant *ms = calloc(1, sizeof(*ms));

	if (ms == NULL)
		goto failure;

	ms->worker_state.mutex = PTHREAD_MUTEX_INITIALIZER;

	ms->worker_state.fd = socket(AF_UNIX,
	    SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (ms->worker_state.fd == -1)
		goto failure;

	ms->worker_state.status = calloc(1, sizeof(*ms->worker_state.status));
	if (ms->worker_state.status == NULL)
		goto failure;

	ms->worker_state.srs = calloc(1, sizeof(*ms->worker_state.srs));
	if (ms->worker_state.srs == NULL)
		goto failure;
	*ms->worker_state.srs = ARRAY_INITIALIZER(scan_results);

	ms->worker_state.kns = calloc(1, sizeof(*ms->worker_state.kns));
	if (ms->worker_state.kns == NULL)
		goto failure;
	*ms->worker_state.kns = ARRAY_INITIALIZER(known_networks);

	ms->sock_dir = strdup("/tmp/mock_ctrl_XXXXXX");
	if (ms->sock_dir == NULL)
		goto failure;
	if (mkdtemp(ms->sock_dir) == NULL)
		goto failure;

	ms->sockaddr.sun_family = AF_UNIX;
	if (snprintf(ms->sockaddr.sun_path, SUNPATHLEN, "%s/sock",
		ms->sock_dir) >= SUNPATHLEN) {
		goto failure;
	}
	ms->sockaddr.sun_len = SUN_LEN(&ms->sockaddr);

	if (bind(ms->worker_state.fd, (struct sockaddr *)&ms->sockaddr,
		ms->sockaddr.sun_len) == -1)
		goto failure;

	ms->worker_state.running = true;
	if (pthread_create(&ms->worker, NULL, mock_supplicant_worker,
		&ms->worker_state) != 0) {
		ms->worker_state.running = false;
		goto failure;
	}

	return (ms);
failure:
	mock_supplicant_destroy(ms);

	return (NULL);
}

void
mock_supplicant_destroy(struct mock_supplicant *ms)
{
	if (ms == NULL)
		return;

	if (ms->worker_state.running) {
		pthread_mutex_lock(&ms->worker_state.mutex);
		ms->worker_state.running = false;
		pthread_mutex_unlock(&ms->worker_state.mutex);
		pthread_join(ms->worker, NULL);
	}

	pthread_mutex_destroy(&ms->worker_state.mutex);

	close(ms->worker_state.fd);

	free_known_networks(ms->worker_state.kns);
	free_scan_results(ms->worker_state.srs);
	free_supplicant_status(ms->worker_state.status);

	if (ms->sockaddr.sun_path[0] != '\0')
		unlink(ms->sockaddr.sun_path);

	if (ms->sock_dir != NULL) {
		rmdir(ms->sock_dir);
		free(ms->sock_dir);
	}

	free(ms);
}

bool
mock_supplicant_set_known_networks(struct mock_supplicant *ms,
    const struct known_networks *kns)
{
	struct known_networks *dup = NULL;

	if (ms == NULL || kns == NULL)
		goto failure;

	if ((dup = calloc(1, sizeof(*dup))) == NULL)
		goto failure;

	for (size_t i = 0; i < kns->len; i++) {
		if (!ARRAY_APPEND(known_networks, dup, kns->items[i]))
			goto failure;
	}

	pthread_mutex_lock(&ms->worker_state.mutex);
	free_known_networks(ms->worker_state.kns);
	ms->worker_state.kns = dup;
	pthread_mutex_unlock(&ms->worker_state.mutex);

	return (true);
failure:
	free_known_networks(dup);

	return (false);
}

bool
mock_supplicant_set_scan_results(struct mock_supplicant *ms,
    const struct scan_results *srs)
{
	struct scan_results *dup = NULL;

	if (ms == NULL || srs == NULL)
		goto failure;

	if ((dup = calloc(1, sizeof(*dup))) == NULL)
		goto failure;

	for (size_t i = 0; i < srs->len; i++) {
		if (!ARRAY_APPEND(scan_results, dup, srs->items[i]))
			goto failure;
	}

	pthread_mutex_lock(&ms->worker_state.mutex);
	free_scan_results(ms->worker_state.srs);
	ms->worker_state.srs = dup;
	pthread_mutex_unlock(&ms->worker_state.mutex);

	return (true);
failure:
	free_scan_results(dup);

	return (false);
}

bool
mock_supplicant_set_status(struct mock_supplicant *ms,
    const struct supplicant_status *status)
{
	struct supplicant_status *dup = NULL;

	if (ms == NULL || status == NULL)
		goto failure;

	if ((dup = calloc(1, sizeof(*dup))) == NULL)
		goto failure;

	dup->freq = status->freq;
	if (status->state != NULL &&
	    (dup->state = strdup(status->state)) == NULL)
		goto failure;
	if (status->bssid != NULL &&
	    (dup->bssid = strdup(status->bssid)) == NULL)
		goto failure;
	if (status->ssid != NULL && (dup->ssid = strdup(status->ssid)) == NULL)
		goto failure;
	if (status->ip_address != NULL &&
	    (dup->ip_address = strdup(status->ip_address)) == NULL)
		goto failure;
	if (status->security != NULL &&
	    (dup->security = strdup(status->security)) == NULL)
		goto failure;

	pthread_mutex_lock(&ms->worker_state.mutex);
	free_supplicant_status(ms->worker_state.status);
	ms->worker_state.status = dup;
	pthread_mutex_unlock(&ms->worker_state.mutex);

	return (true);
failure:
	free_supplicant_status(dup);

	return (false);
}

struct wpa_ctrl *
wpa_ctrl_open_mock(struct mock_supplicant *ms)
{
	if (ms == NULL)
		return (NULL);

	return (wpa_ctrl_open(ms->sockaddr.sun_path));
}

static void *
mock_supplicant_worker(void *arg)
{
	return (NULL);
}
