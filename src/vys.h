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
#ifndef VYS_H_
#define VYS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>

#define VYS_MULTICAST_ADDRESS_SIZE 32
#define VYS_DATA_DIGEST_SIZE 16

struct vys_spectrum_info {
	uint64_t data_addr;
	uint64_t timestamp;
	uint8_t digest[VYS_DATA_DIGEST_SIZE];
};

struct vys_signal_msg_payload {
	struct sockaddr_in sockaddr;
	uint16_t num_channels;
	uint8_t stations[2];
	uint8_t spectral_window_index;
	uint8_t stokes_index;
	uint8_t mr_id;
	uint8_t num_spectra;
	struct vys_spectrum_info infos[];
};

struct vys_signal_msg {
	struct ibv_grh grh;
	struct vys_signal_msg_payload payload;
};

#define SIZEOF_VYS_SIGNAL_MSG_PAYLOAD(n)                                \
	(sizeof(struct vys_signal_msg_payload) + \
	 ((n) * sizeof(struct vys_spectrum_info)))

#define SIZEOF_VYS_SIGNAL_MSG(n)                                        \
	(sizeof(struct vys_signal_msg) + \
	 ((n) * sizeof(struct vys_spectrum_info)))

struct vys_error_record {
	int errnum;
	char *desc;
	struct vys_error_record *next;
};

struct vys_configuration {
	struct vys_error_record *error_record;

	/* multicast address for signal messages; expected format is dotted quad IP
	 * address string */
	char signal_multicast_address[VYS_MULTICAST_ADDRESS_SIZE];
};

extern struct vys_configuration *vys_configuration_new(
	const char *path)
	__attribute__((malloc,returns_nonnull));
extern void vys_configuration_free(struct vys_configuration *config)
	__attribute__((nonnull));

extern struct vys_error_record *vys_error_record_new(
	struct vys_error_record *tail, int errnum, char *desc)
	__attribute__((nonnull(3),returns_nonnull,malloc));
extern struct vys_error_record *vys_error_record_desc_dup(
	struct vys_error_record *tail, int errnum, const char *desc)
	__attribute__((nonnull(3),returns_nonnull,malloc));
extern struct vys_error_record *vys_error_record_desc_dup_printf(
	struct vys_error_record *tail, int errnum, const char *format, ...)
	__attribute__((nonnull(3),returns_nonnull,malloc,format(printf,3,4)));
extern void vys_error_record_free(struct vys_error_record *record);
extern struct vys_error_record *vys_error_record_reverse(
	struct vys_error_record *record);
extern struct vys_error_record *vys_error_record_concat(
	struct vys_error_record *first, struct vys_error_record *second);
extern char *vys_error_record_to_string(
	struct vys_error_record **record)
	__attribute__((malloc,returns_nonnull,nonnull));

extern char *vys_get_ipoib_addr(void)
	__attribute__((malloc,nonnull));

#define MSG_ERROR(records, err, format, ...)                            \
	{ *(records) = \
			vys_error_record_desc_dup_printf( \
				*(records), (err), G_STRLOC ": " format, ##__VA_ARGS__); }

#define VERB_ERR(records, err, fn)                                      \
	MSG_ERROR(records, err, "%s failed: %s", fn, strerror(err))

#ifdef __cplusplus
}
#endif
	
#endif /* VYS_H_ */
