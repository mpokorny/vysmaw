#include <buffer_pool.h>
#include <glib.h>

struct buffer_pool *
buffer_pool_new(size_t num_buffers, size_t buffer_size)
{
	g_assert(buffer_size >= sizeof(struct buffer_stack));
	struct buffer_pool *result = g_new(struct buffer_pool, 1);
	result->buffer_size = buffer_size;
	result->pool = g_malloc_n(num_buffers, buffer_size);
	result->pool_size = num_buffers * buffer_size;
	result->root = (struct buffer_stack *)result->pool;
	struct buffer_stack *buff = result->root;
	struct buffer_stack *next_buff = (void *)buff + buffer_size;
	for (size_t i = num_buffers; i > 1; --i) {
		buff->next = next_buff;
		buff = next_buff;
		next_buff = (void *)buff + buffer_size;
	}
	buff->next = NULL;
#if BUFFER_POOL_LOCK
	g_mutex_init(&result->lock);
#endif
	return result;
}

void
buffer_pool_free(struct buffer_pool *buffer_pool)
{
	g_free(buffer_pool->pool);
#if BUFFER_POOL_LOCK
	g_mutex_clear(&buffer_pool->lock);
#endif
	g_free(buffer_pool);
}
