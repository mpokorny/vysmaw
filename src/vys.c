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
