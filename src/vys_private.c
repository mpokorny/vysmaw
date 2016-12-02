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

static gchar *default_config_vys()
	__attribute__((returns_nonnull,malloc));

static gchar *
default_config_vys()
{
	GKeyFile *kf = g_key_file_new();
	g_key_file_set_string(kf, VYS_CONFIG_GROUP_NAME,
	                      SIGNAL_MULTICAST_ADDRESS_KEY,
	                      VYS_SIGNAL_MULTICAST_ADDRESS);
	gchar *result = g_key_file_to_data(kf, NULL, NULL);
	g_key_file_free(kf);
	return result;
}

char *
load_config(const char *path, struct vys_error_record **error_record)
{
	gchar *result = NULL;
	if (path != NULL) {
		GKeyFile *kf = g_key_file_new();
		GError *err = NULL;
		if (g_key_file_load_from_file(kf, path, G_KEY_FILE_NONE, &err)) {
			result = g_key_file_to_data(kf, NULL, NULL);
		} else {
			if (error_record != NULL)
				MSG_ERROR(error_record, -1,
				          "Failed to load configuration file '%s': %s",
				          path, err->message);
			g_error_free(err);
		}
		g_key_file_free(kf);
	}
	if (result == NULL)
		result = g_strdup("");
	return result;
}

char *
config_vys_base(void)
{
	char *dcfg = default_config_vys();
	char *fcfg = load_config(VYS_CONFIG_PATH, NULL);
	char *result = g_strjoin("\n", dcfg, fcfg, NULL);
	g_free(fcfg);
	g_free(dcfg);
	return result;
}
