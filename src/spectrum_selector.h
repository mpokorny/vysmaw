#ifndef SPECTRUM_SELECTOR_H_
#define SPECTRUM_SELECTOR_H_

#include <vysmaw_private.h>

struct spectrum_selector_context {
	vysmaw_handle handle;

	GAsyncQueue *signal_msg_queue;
	GAsyncQueue *read_request_queue;
	struct buffer_pool *signal_msg_buffers;
	unsigned signal_msg_num_spectra;
};

void *spectrum_selector(struct spectrum_selector_context *context);

#endif /* SPECTRUM_SELECTOR_H_ */
