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
#include <spectrum_selector.h>
#include <glib.h>

#define MIN_EAGER_CONNECT_IDLE_SEC 0.1

static bool select_spectra(
	struct data_path_message *msg, struct consumer *consumers,
	unsigned num_consumers)
	__attribute__((nonnull));

static bool
select_spectra(struct data_path_message *msg, struct consumer *consumers,
               unsigned num_consumers)
{
	g_assert(msg->typ == DATA_PATH_SIGNAL_MSG);

	const struct vys_signal_msg_payload *payload = &msg->signal_msg->payload;

	bool result = false;
	for (unsigned i = 0; i < payload->num_spectra; ++i)
		msg->consumers[i] = NULL;

	struct consumer *consumer = consumers;
	while (num_consumers-- > 0) {
		g_array_set_size(consumer->pass_filter_array, payload->num_spectra);
		bool *pass_filter = (bool *)consumer->pass_filter_array->data;
		consumer->spectrum_filter_fn(
			payload->stations,
			payload->spectral_window_index,
			payload->baseband_id,
			payload->polarization_product_id,
			payload->infos,
			payload->num_spectra,
			consumer->user_data,
			pass_filter);
		for (unsigned j = 0; j < payload->num_spectra; ++j)
			if (*pass_filter++) {
				result = true;
				msg->consumers[j] =
					g_slist_prepend(msg->consumers[j], consumer);
			}
		consumer++;
	}
	return result;
}


#define READY(gate) G_STMT_START {                                      \
		MUTEX_LOCK((gate)->mtx); \
		(gate)->spectrum_selector_ready = true; \
		COND_SIGNAL((gate)->cond); \
		MUTEX_UNLOCK((gate)->mtx); \
	} G_STMT_END

void *
spectrum_selector(struct spectrum_selector_context *context)
{
	/* maintain a table of times that an eager connection request to each server
	 * was last requested */
	GHashTable *prev_eagerly_forwarded =
		g_hash_table_new_full((GHashFunc)sockaddr_hash,
		                      (GEqualFunc)sockaddr_equal,
		                      (GDestroyNotify)free_sockaddr_key,
		                      (GDestroyNotify)g_timer_destroy);

	READY(&context->handle->gate);

	double eager_connect_idle_sec =
		MIN(context->handle->config.eager_connect_idle_sec,
		    MIN_EAGER_CONNECT_IDLE_SEC);
	bool quitting = false;
	bool quit = false;
	while (!quit) {
		struct data_path_message *msg =
			g_async_queue_pop(context->signal_msg_queue);

		switch (msg->typ) {
		case DATA_PATH_SIGNAL_MSG: {
			bool selected =
				!quitting
				&& select_spectra(
					msg,
					context->handle->consumers,
					context->handle->num_consumers);
			if (!selected && context->handle->config.eager_connect) {
				/* may want to forward the signal message if eager connections
				 * are configured */
				GTimer *t = g_hash_table_lookup(
					prev_eagerly_forwarded,
					&msg->signal_msg->payload.sockaddr);
				if (t == NULL) {
					t = g_timer_new();
					g_hash_table_insert(
						prev_eagerly_forwarded,
						new_sockaddr_key(&msg->signal_msg->payload.sockaddr),
						t);
					selected = true;
				} else {
					if (g_timer_elapsed(t, NULL) >= eager_connect_idle_sec) {
						selected = true;
						g_timer_start(t);
					}
				}
			}
			if (selected) {
				vys_async_queue_push(context->read_request_queue, msg);
			} else {
				vys_buffer_pool_push(context->signal_msg_buffers,
				                     msg->signal_msg);
				data_path_message_free(msg);
			}
			break;
		}
		case DATA_PATH_QUIT:
			quitting = true;
			vys_async_queue_push(context->read_request_queue, msg);
			break;

		case DATA_PATH_END:
			quit = true;
			vys_async_queue_push(context->read_request_queue, msg);
			break;

		default:
			vys_async_queue_push(context->read_request_queue, msg);
			break;
		}
	}

	g_hash_table_destroy(prev_eagerly_forwarded);
	g_async_queue_unref(context->signal_msg_queue);
	vys_async_queue_unref(context->read_request_queue);
	g_free(context);
	return NULL;
}
