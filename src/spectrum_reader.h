#ifndef SPECTRUM_READER_H_
#define SPECTRUM_READER_H_

#include <vysmaw_private.h>

struct spectrum_reader_context {
	vysmaw_handle handle;

	unsigned signal_msg_num_spectra;
	struct buffer_pool *signal_msg_buffers;

	GAsyncQueue *read_request_queue;

	int loop_fd;
};

void *spectrum_reader(struct spectrum_reader_context *context);

#endif /* SPECTRUM_READER_H_ */
