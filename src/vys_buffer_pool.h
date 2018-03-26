/* -*- mode: c; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
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
#ifndef __VYS_BUFFER_POOL_H__
#define __VYS_BUFFER_POOL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <glib.h>

struct vys_buffer_stack;

struct vys_buffer_stack {
  struct vys_buffer_stack *next;
};

struct vys_buffer_pool {
  size_t buffer_size;
  size_t pool_size;
  void *pool;
  struct vys_buffer_stack *root;
};

#define VYS_BUFFER_POOL_MIN_BUFFER_SIZE (sizeof(struct vys_buffer_stack))

struct vys_buffer_pool *vys_buffer_pool_new(
  size_t num_buffers, size_t buffer_size)
  __attribute__((returns_nonnull,malloc));

void vys_buffer_pool_free(struct vys_buffer_pool *buffer_pool)
  __attribute__((nonnull));

static inline void
vys_buffer_pool_push(struct vys_buffer_pool *buffer_pool, void *data_p)
{
  struct vys_buffer_stack *new_root = data_p;
  struct vys_buffer_stack *root;
  do {
    root = g_atomic_pointer_get(&buffer_pool->root);
    new_root->next = root;
  } while (!g_atomic_pointer_compare_and_exchange(
             (void **)&buffer_pool->root, root, new_root));
}

static inline void *
vys_buffer_pool_pop(struct vys_buffer_pool *buffer_pool)
{
  struct vys_buffer_stack *root;
  struct vys_buffer_stack *new_root;
  do {
    root = g_atomic_pointer_get(&buffer_pool->root);
    new_root = (root ? root->next : root);
  } while (root != NULL &&
           !g_atomic_pointer_compare_and_exchange(
             (void **)&buffer_pool->root, root, new_root));
  if (root) root->next = NULL;
  return root;
}

static inline void *
vys_buffer_pool_pop_nonnull(struct vys_buffer_pool *buffer_pool)
{
  void *result;
  do {
    result = vys_buffer_pool_pop(buffer_pool);
  } while (result == NULL);
  return result;
}

#ifdef __cplusplus
}
#endif

#endif /* __VYS_BUFFER_POOL_H_ */
