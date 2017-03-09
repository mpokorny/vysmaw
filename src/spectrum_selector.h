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
#ifndef SPECTRUM_SELECTOR_H_
#define SPECTRUM_SELECTOR_H_

#include <vysmaw_private.h>
#include <vys_buffer_pool.h>
#include <vys_async_queue.h>

struct spectrum_selector_context {
	vysmaw_handle handle;

	GAsyncQueue *signal_msg_queue;
	struct vys_async_queue *read_request_queue;
	struct vys_buffer_pool *signal_msg_buffers;
	unsigned signal_msg_num_spectra;
};

void *spectrum_selector(struct spectrum_selector_context *context);

#endif /* SPECTRUM_SELECTOR_H_ */
