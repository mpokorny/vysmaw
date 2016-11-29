#ifndef __BUFFER_POOL_H__
#define __BUFFER_POOL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <glib.h>

struct buffer_stack;

struct buffer_stack {
	struct buffer_stack *next;
};

/* define BUFFER_POOL_LOCK for an implementation using a mutex lock, instead of
 * the default lockless implementation */
#undef BUFFER_POOL_LOCK

struct buffer_pool {
	size_t buffer_size;
	size_t pool_size;
	void *pool;
	struct buffer_stack *root;
#if BUFFER_POOL_LOCK
	GMutex lock;
#endif
};

struct buffer_pool *buffer_pool_new(size_t num_buffers, size_t buffer_size)
	__attribute__((returns_nonnull,malloc));

void buffer_pool_free(struct buffer_pool *buffer_pool)
	__attribute__((nonnull));

static inline void
buffer_pool_push(struct buffer_pool *buffer_pool, void *data_p)
{
	struct buffer_stack *new_root = data_p;
#if BUFFER_POOL_LOCK
	g_mutex_lock(&buffer_pool->lock);
	new_root->next = buffer_pool->root;
	buffer_pool->root = new_root;
	g_mutex_unlock(&buffer_pool->lock);
#else
	struct buffer_stack *root;
	do {
		root = g_atomic_pointer_get(&buffer_pool->root);
		new_root->next = root;
	} while (!g_atomic_pointer_compare_and_exchange(
		         (void **)&buffer_pool->root, root, new_root));
#endif
}

static inline void *
buffer_pool_pop(struct buffer_pool *buffer_pool)
{
	struct buffer_stack *root;
#if BUFFER_POOL_LOCK
	g_mutex_lock(&buffer_pool->lock);
	root = buffer_pool->root;
	buffer_pool->root = (root ? root->next : root);
	g_mutex_unlock(&buffer_pool->lock);
#else
	struct buffer_stack *new_root;
	do {
		root = g_atomic_pointer_get(&buffer_pool->root);
		new_root = (root ? root->next : root);
	} while (root != NULL &&
	         !g_atomic_pointer_compare_and_exchange(
		         (void **)&buffer_pool->root, root, new_root));
#endif
	if (root) root->next = NULL;
	return root;
}

static inline void *
buffer_pool_pop_nonnull(struct buffer_pool *buffer_pool)
{
	void *result;
	do {
		result = buffer_pool_pop(buffer_pool);
	} while (result == NULL);
	return result;
}

#ifdef __cplusplus
}
#endif

#endif /* __BUFFER_POOL_H_ */
