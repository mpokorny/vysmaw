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
#include <vys_private.h>
#include <glib.h>
#include <string.h>

struct vys_configuration *
vys_configuration_new(const char *path)
{
	struct vys_configuration *result = g_new0(struct vys_configuration, 1);
	gchar *base = config_vys_base();
	gchar *pcfg = load_config(path, &(result->error_record));
	if (result->error_record == NULL) {
		/* merge base config and config loaded from path */
		gchar *cfg = g_strjoin("\n", base, pcfg, NULL);
		GKeyFile *kf = g_key_file_new();
		if (g_key_file_load_from_data(kf, cfg, -1, G_KEY_FILE_NONE, NULL)) {
			/* parse the merged configuration */
			init_from_key_file_vys(kf, result);
		} else {
			MSG_ERROR(&(result->error_record), -1, "%s",
			          "Failed to merge configuration files");
		}
		g_key_file_free(kf);
		g_free(cfg);
	}
	g_free(base);
	g_free(pcfg);
	return result;
}

void
vys_configuration_free(struct vys_configuration *config)
{
	vys_error_record_free(config->error_record);
	g_free(config);
}

struct vys_error_record *
vys_error_record_new(struct vys_error_record *tail, int errnum, char *desc)
{
	struct vys_error_record *result = g_slice_new(struct vys_error_record);
	result->errnum = errnum;
	result->desc = desc;
	result->next = tail;
	return result;
}

struct vys_error_record *
vys_error_record_desc_dup(struct vys_error_record *tail,
                          int errnum, const char *desc)
{
	return vys_error_record_new(tail, errnum, g_strdup(desc));
}

struct vys_error_record *
vys_error_record_desc_dup_printf(struct vys_error_record *tail,
                                 int errnum, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	struct vys_error_record *result =
		vys_error_record_new(tail, errnum, g_strdup_vprintf(format, ap));
	va_end(ap);
	return result;
}

void
vys_error_record_free(struct vys_error_record *record)
{
	while (record != NULL) {
		g_free(record->desc);
		struct vys_error_record *next = record->next;
		g_slice_free(struct vys_error_record, record);
		record = next;
	}
}

struct vys_error_record *
vys_error_record_reverse(struct vys_error_record *record)
{
	struct vys_error_record *result = NULL;
	while (record != NULL) {
		struct vys_error_record *next = record->next;
		record->next = result;
		result = record;
		record = next;
	}
	return result;
}

struct vys_error_record *
vys_error_record_concat(struct vys_error_record *first,
                        struct vys_error_record *second)
{
	struct vys_error_record *result;
	if (first != NULL) {
		result = first;
		while (first->next != NULL)
			first = first->next;
		first->next = second;
	} else {
		result = second;
	}
	return result;
}

char *
vys_error_record_to_string(struct vys_error_record **record)
{
	*record = vys_error_record_reverse(*record);
	GString *str = g_string_new("");
	struct vys_error_record *er = *record;
	while (er != NULL) {
		g_string_append_printf(str, "%s\n", er->desc);
		er = er->next;
	}
	return g_string_free(str, FALSE);
}

void
vys_signal_msg_payload_init(struct vys_signal_msg_payload *payload,
                            const char *config_id)
{
	payload->vys_version = VYS_VERSION;
	if (strlen(config_id) >= sizeof(payload->config_id))
		config_id += strlen(config_id) + 1 - sizeof(payload->config_id);
	g_strlcpy(payload->config_id, config_id, sizeof(payload->config_id));
}

char *
vys_get_ipoib_addr(void)
{
	char *result = NULL;
	struct ifaddrs *ifap0 = NULL;
	int rc = getifaddrs(&ifap0);
	if (G_LIKELY(rc == 0)) {
		struct ifaddrs *ifap1 = ifap0;
		while (result == NULL && ifap1 != NULL) {
			if (ifap1->ifa_addr->sa_family == AF_PACKET) {
				struct sockaddr_ll *sockaddr_ll =
					(struct sockaddr_ll *)(ifap1->ifa_addr);
				if (sockaddr_ll->sll_hatype == ARPHRD_INFINIBAND) {
					struct ifaddrs *ifap2 = ifap0;
					while (result == NULL && ifap2 != NULL) {
						if (ifap2->ifa_addr->sa_family == AF_INET &&
						    strcmp(ifap1->ifa_name, ifap2->ifa_name) == 0) {
							struct sockaddr_in *sockaddr_in =
								(struct sockaddr_in *)(ifap2->ifa_addr);
							char *cp = inet_ntoa(sockaddr_in->sin_addr);
							result = g_strdup(cp);
						}
						ifap2 = ifap2->ifa_next;
					}
				}
			}
			ifap1 = ifap1->ifa_next;
		}
		freeifaddrs(ifap0);
	}
	return result;
}

extern size_t vys_spectrum_buffer_size(
    uint16_t num_channels, uint16_t num_bins, uint16_t bin_stride);
extern size_t vys_spectrum_max_buffer_size(
    uint16_t num_channels, uint16_t num_bins);
