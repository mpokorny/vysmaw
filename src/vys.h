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

#define VYS_VERSION 4

#define VYS_MULTICAST_ADDRESS_SIZE 32
#define VYS_CONFIG_ID_SIZE 60
#define VYS_SPECTRUM_OFFSET 32

struct vys_spectrum_info {
	uint64_t data_addr;
	uint64_t timestamp;
	uint32_t id_num;
};

/* polarization product definitions
 *
 * Labels "A" and "B" correspond to either L/R or X/Y polarization pairs,
 * depending on the observing band: "A/B" is either "R/L" or "Y/X".
 */
#define VYS_POLARIZATION_PRODUCT_AA 0
#define VYS_POLARIZATION_PRODUCT_AB 1
#define VYS_POLARIZATION_PRODUCT_BA 2
#define VYS_POLARIZATION_PRODUCT_BB 3
#define VYS_POLARIZATION_PRODUCT_UNKNOWN 4

/* baseband definitions
 */
#define VYS_BASEBAND_A1C1_3BIT 0
#define VYS_BASEBAND_A2C2_3BIT 1
#define VYS_BASEBAND_AC_8BIT 2
#define VYS_BASEBAND_B1D1_3BIT 3
#define VYS_BASEBAND_B2D2_3BIT 4
#define VYS_BASEBAND_BD_8BIT 5
#define VYS_BASEBAND_UNKNOWN 6

struct vys_signal_msg_payload {
	uint16_t vys_version; /* present as first field in all versions */
	struct sockaddr_in sockaddr;
	char config_id[VYS_CONFIG_ID_SIZE];
	uint16_t num_channels;
	uint16_t num_bins;
	uint16_t bin_stride; /* in number of channels */
	uint8_t stations[2];
	uint8_t baseband_index;
	uint8_t baseband_id;
	uint8_t spectral_window_index;
	uint8_t polarization_product_id;
	uint8_t mr_id;
	uint8_t num_spectra;
	struct vys_spectrum_info infos[];
};

struct vys_signal_msg {
	struct ibv_grh grh;
	struct vys_signal_msg_payload payload;
};

#define SIZEOF_VYS_SIGNAL_MSG_PAYLOAD(n)		\
	(sizeof(struct vys_signal_msg_payload) +	\
	 ((n) * sizeof(struct vys_spectrum_info)))

#define SIZEOF_VYS_SIGNAL_MSG(n)				\
	(sizeof(struct vys_signal_msg) +			\
	 ((n) * sizeof(struct vys_spectrum_info)))

#define MAX_VYS_SIGNAL_MSG_LENGTH(sz)			\
	(((sz) > sizeof(struct vys_signal_msg))		\
	 ? (((sz) - sizeof(struct vys_signal_msg))	\
	    / sizeof(struct vys_spectrum_info))		\
	 : 0)

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

extern void vys_signal_msg_payload_init(
	struct vys_signal_msg_payload *payload, const char *config_id)
	__attribute__((nonnull));

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
