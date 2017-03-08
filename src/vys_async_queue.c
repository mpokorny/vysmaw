//
// Copyright © 2016 Associated Universities, Inc. Washington DC, USA.
//
// This file is part of vysmaw.
//
// vysmaw is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// vysmaw is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// vysmaw.  If not, see <http://www.gnu.org/licenses/>.
//
#include <unistd.h>
#include <errno.h>
#ifndef _GNU_SOURCE
# include <fcntl.h>
#endif
#include <string.h>
#include <async_queue.h>

#define POP_FD(q) ((q)->fds[0])
#define PUSH_FD(q) ((q)->fds[1])

struct async_queue *
new_no_queue()
{
	struct async_queue *result = g_try_new(struct async_queue, 1);
	if (G_LIKELY(result != NULL)) {
		result->refcount = 1;
		int rc;
#ifdef _GNU_SOURCE
		rc = pipe2(result->fds, O_NONBLOCK);
#else
		rc = pipe(result->fds);
		if (G_LIKELY(rc == 0))
			rc = fcntl(result->fds[0], F_SETFL, O_NONBLOCK);
		if (G_LIKELY(rc == 0))
			rc = fcntl(result->fds[1], F_SETFL, O_NONBLOCK);
#endif
		if (G_UNLIKELY(rc != 0)) {
			g_free(result);
			result = NULL;
		}
	} else {
		errno = ENOMEM;
	}
	return result;
}

struct async_queue *
async_queue_new()
{
	struct async_queue *result = new_no_queue();
	if (G_LIKELY(result != NULL))
		result->q = g_async_queue_new();
	return result;
}

struct async_queue *
async_queue_new_full(GDestroyNotify destroy)
{
	struct async_queue *result = new_no_queue();
	if (G_LIKELY(result != NULL))
		result->q = g_async_queue_new_full(destroy);
	return result;
}

struct async_queue *
async_queue_ref(struct async_queue *queue)
{
	g_atomic_int_inc(&queue->refcount);
	return queue;
}

void
async_queue_unref(struct async_queue *queue)
{
	if (g_atomic_int_dec_and_test(&queue->refcount)) {
		g_async_queue_unref(queue->q);
		int rc1 = close(queue->fds[0]);
		int errno1 = errno;
		int rc = close(queue->fds[1]);
		if (G_UNLIKELY(rc == 0 && rc1 != 0))
			errno = errno1;
		g_free(queue);
	}
}

void
async_queue_push(struct async_queue *queue, void *item)
{
	g_async_queue_push(queue->q, item);
	unsigned u;
	size_t w = 0;
	ssize_t n;
	do {
		errno = 0;
		n = write(PUSH_FD(queue), (void *)&u + w, sizeof(u) - w);
		if (G_LIKELY(n >= 0)) w += n;
	} while (errno == EINTR || w != sizeof(u));
	if (G_UNLIKELY(errno != 0))
		g_error("async_queue_push write failed: %s", strerror(errno));
}

void *
async_queue_pop(struct async_queue *queue)
{
	unsigned u;
	size_t r = 0;
	ssize_t n;
	do {
		errno = 0;
		n = read(POP_FD(queue), (void *)&u + r, sizeof(u) - r);
		if (G_LIKELY(n >= 0)) r += n;
	} while (errno == EINTR || r != sizeof(u));
	if (G_UNLIKELY(errno != 0))
		g_error("async_queue_pop read failed: %s", strerror(errno));
	return g_async_queue_pop(queue->q);
}

int
async_queue_pop_fd(struct async_queue *queue)
{
	return POP_FD(queue);
}

int
async_queue_push_fd(struct async_queue *queue)
{
	return PUSH_FD(queue);
}
