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

	ARRAY_FREE(ms->worker_state.kns);
	free(ms->worker_state.kns);

	ARRAY_FREE(ms->worker_state.srs);
	free(ms->worker_state.srs);

	free_supplicant_status(ms->worker_state.status);

	if (ms->sockaddr.sun_path[0] != '\0')
		unlink(ms->sockaddr.sun_path);

	if (ms->sock_dir != NULL) {
		rmdir(ms->sock_dir);
		free(ms->sock_dir);
	}

	free(ms);
}

static void *
mock_supplicant_worker(void *arg)
{
	return (NULL);
}
