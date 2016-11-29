#ifndef SIGNAL_RECEIVER_H_
#define SIGNAL_RECEIVER_H_

#include <vysmaw_private.h>

struct signal_receiver_context {
	vysmaw_handle handle;

	GAsyncQueue *signal_msg_queue;

	unsigned signal_msg_num_spectra;
	struct buffer_pool *signal_msg_buffers;

	int loop_fd;
};

void *signal_receiver(struct signal_receiver_context *context);

#endif /* SIGNAL_RECEIVER_H_ */
