/*
* Copyright 2019-present Open Networking Foundation
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#include <stdio.h>
#include <sys/inotify.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <string.h>
#include <monitor_config.h>
#include <rte_log.h>
#include "cp.h"

#define MAX_FILE_PATH 128
struct entry
{
	configCbk    callback;
	char         config_file[MAX_FILE_PATH];
};
pthread_t  config_monitor_tid;

void *config_thread_handler(void *config);

static bool
handle_events(int fd, int *wd, struct entry *config)
{
	bool handled = false;
	static char buf[4096];
	const struct inotify_event *event;
	ssize_t len;
	char *ptr;

	/* Loop while events can be read from inotify file descriptor. */
	RTE_LOG_DP(INFO, CP, "Received file event for %s \n", config->config_file);
	/* Read some events. */
	len = read(fd, buf, sizeof buf);
	/* If the nonblocking read() found no events to read, then
	   it returns -1 with errno set to EAGAIN. In that case,
	   we exit the loop. */
	if (len == -1 && errno != EAGAIN) {
		rte_exit(EXIT_FAILURE, "Failed to read!\n");
	}

	if (len <= 0) {
		RTE_LOG_DP(DEBUG, CP, "inotify read config change len <= 0 \n ");
		return handled; 
	}

	/* Loop over all events in the buffer */
	for (ptr = buf; ptr < buf + len;
	     ptr += sizeof(struct inotify_event) + event->len) {

		event = (const struct inotify_event *) ptr;
		RTE_LOG_DP(DEBUG, CP, "event mask %x: \n", event->mask);

		/* Print event type */
		if (event->mask & IN_ACCESS) {
			RTE_LOG_DP(DEBUG, CP, "IN_ACCESS: \n");
			continue;
		}
		if (event->mask & IN_CLOSE_NOWRITE) {
			RTE_LOG_DP(DEBUG, CP, "IN_CLOSE_NOWRITE: \n");
			continue;
		}
		if (event->mask & IN_OPEN) {
			RTE_LOG_DP(DEBUG, CP, "IN_OPEN: skip \n");
			continue;
		}
		if (event->mask & IN_ATTRIB) {
			RTE_LOG_DP(DEBUG, CP, "IN_ATTRIB: \n");
		}
		if (event->mask & IN_CLOSE_WRITE) {
			RTE_LOG_DP(DEBUG, CP, "IN_CLOSE_WRITE: \n");
		}
		if (event->mask & IN_CREATE) {
			RTE_LOG_DP(DEBUG, CP, "IN_CREATE: \n");
		}
		if (event->mask & IN_DELETE) {
			RTE_LOG_DP(DEBUG, CP, "IN_DELETE: \n");
		}
		if (event->mask & IN_DELETE_SELF) {
			RTE_LOG_DP(DEBUG, CP, "IN_DELETE_SELF: \n");
		}
		if (event->mask & IN_MODIFY) {
			RTE_LOG_DP(DEBUG, CP, "IN_MODIFY: \n");
		}
		if (event->mask & IN_MOVE_SELF) {
			RTE_LOG_DP(DEBUG, CP, "IN_MOVE_SELF: \n");
		}
		if (event->mask & IN_MOVED_FROM)
			RTE_LOG_DP(DEBUG, CP, "IN_MOVED_FROM: \n");

		if (event->mask & IN_MOVED_TO) {
				RTE_LOG_DP(DEBUG, CP, "IN_MOVED_TO: \n");
		}
		if (event->mask & IN_IGNORED) {
			RTE_LOG_DP(DEBUG, CP, "IN_IGNORE: file deleted \n");
		}

		if (wd[0] == event->wd) {
			RTE_LOG_DP(DEBUG, CP, "calling config change callback \n");
			handled = true;
			config->callback(config->config_file, 0);
			break;
		}
	}
	return handled;
}

void *
config_thread_handler(void *config)
{
	nfds_t nfds;
	int poll_num;
	struct pollfd fds[1];
	int wd;
	struct entry *cfg = (struct entry *)config;
	int fd = 0;

	RTE_LOG_DP(INFO, CP, "Thread started for monitoring config file %s\n",
		   cfg->config_file);

	fd = inotify_init1(IN_NONBLOCK);
	if (fd == -1) {
		perror("inotify_init1");
		exit(EXIT_FAILURE);
	}

	wd = inotify_add_watch(fd, cfg->config_file, IN_ALL_EVENTS); //OPEN | IN_CLOSE);
	if (wd == -1) {
		RTE_LOG_DP(ERR, CP, "Can not watch file. File does not exist - %s \n",
			cfg->config_file);
		return NULL;
	}
	RTE_LOG_DP(INFO, CP, "add_watch return %d \n", wd);

	/* Prepare for polling */
	nfds = 1;

	/* Inotify input */
	fds[0].fd = fd;
	fds[0].events = POLLIN;

	/* Wait for events and/or terminal input */

	while (true) {
		// -1 timeout means we wait till event received.
		// That also means no tight looping
		poll_num = poll(fds, nfds, 100);
		if (poll_num == -1) {
			if (errno == EINTR)
				continue;
			perror("poll");
			exit(EXIT_FAILURE);
		} else if (poll_num > 0) {
			if (fds[0].revents & POLLIN) {
				/* Inotify events are available */
				bool handled = handle_events(fd, &wd, cfg);
				if (handled == true) {
					RTE_LOG_DP(INFO, CP, "FILE change handled \n");
					/* One time event. Exit from the thread  */
					return NULL;
				}
			}
		}
	}
	return NULL;
}

/* Create fd and add it into the link list */
void
watch_config_change(const char *config_file, configCbk cbk)
{
	pthread_attr_t attr;

	RTE_LOG_DP(INFO, CP, "Register config change notification %s\n", config_file);

	struct entry *config_entry = (struct entry *) calloc(1, sizeof(struct entry));
	if (config_entry == NULL) {
		rte_exit(EXIT_FAILURE, "Could not allocate memory for config entry!\n");
	}
	strncpy(config_entry->config_file, config_file, strlen(config_file));
	config_entry->callback = cbk;

	pthread_attr_init(&attr);
	/* Create a thread which will monitor changes in the config file */
	if (pthread_create(&config_monitor_tid, &attr, &config_thread_handler, config_entry) != 0) {
		rte_exit(EXIT_FAILURE, "Failed to spawn app config thread!\n");
	}
	pthread_attr_destroy(&attr);
	return;
}
