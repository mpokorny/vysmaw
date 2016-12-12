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
#ifndef ASYNC_QUEUE_H_
#define ASYNC_QUEUE_H_

#include <glib.h>

struct async_queue {
	int refcount;
	int fds[2];
	GAsyncQueue *q;
};

extern struct async_queue *async_queue_new()
	__attribute__((malloc));
extern struct async_queue *async_queue_new_full(GDestroyNotify destroy)
	__attribute__((nonnull,malloc));
extern struct async_queue *async_queue_ref(struct async_queue *queue)
	__attribute__((nonnull,returns_nonnull));
extern void async_queue_unref(struct async_queue *queue)
	__attribute__((nonnull));
extern void async_queue_push(struct async_queue *queue, void *item)
	__attribute__((nonnull));
extern void *async_queue_pop(struct async_queue *queue)
	__attribute__((nonnull,returns_nonnull));
extern int async_queue_pop_fd(struct async_queue *queue)
	__attribute__((nonnull));
extern int async_queue_push_fd(struct async_queue *queue)
	__attribute__((nonnull));

#endif /* ASYNC_QUEUE_H_ */
