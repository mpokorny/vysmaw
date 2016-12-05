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

void
init_from_key_file_vys(GKeyFile *kf, struct vys_configuration *config)
{
	GError *err = NULL;
	gchar *mc_addr = g_key_file_get_string(
		kf, VYS_CONFIG_GROUP_NAME, SIGNAL_MULTICAST_ADDRESS_KEY, &err);
	if (err == NULL) {
		g_assert(mc_addr != NULL);
		gsize mc_addr_len =
			g_strlcpy(config->signal_multicast_address, mc_addr,
			          sizeof(config->signal_multicast_address));
		g_free(mc_addr);
		/* check that value is not too long */
		if (mc_addr_len >= sizeof(config->signal_multicast_address))
			MSG_ERROR(&(config->error_record), -1,
			          "'%s' field value is too long",
			          SIGNAL_MULTICAST_ADDRESS_KEY);
	} else {
		MSG_ERROR(&(config->error_record), -1,
		          "Failed to parse '%s' field: %s",
		          SIGNAL_MULTICAST_ADDRESS_KEY,
		          err->message);
		g_error_free(err);
	}
}

int
set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
