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
#include <vys.h>
#include <glib.h>
#include <stdio.h>
#include <string.h>

#define SIGNAL_MULTICAST_ADDRESS_KEY "signal_multicast_address"

static gchar *load_config(const gchar *path, GError **error)
	__attribute__((malloc));
static gchar *default_config()
	__attribute__((returns_nonnull,malloc));
struct vys_configuration *init_from_key_file(GKeyFile *kf)
	__attribute__((nonnull,malloc));

static gchar *
load_config(const gchar *path, GError **error)
{
	gchar *result = NULL;
	if (path != NULL) {
		GKeyFile *kf = g_key_file_new();
		if (g_key_file_load_from_file(kf, path, G_KEY_FILE_NONE, error))
			result = g_key_file_to_data(kf, NULL, NULL);
		g_key_file_free(kf);
	}
	if (result == NULL)
		result = g_strdup("");
	return result;
}

static gchar *
default_config()
{
	GKeyFile *kf = g_key_file_new();
	g_key_file_set_string(kf, VYS_CONFIG_GROUP_NAME,
	                      SIGNAL_MULTICAST_ADDRESS_KEY,
	                      VYS_SIGNAL_MULTICAST_ADDRESS);
	gchar *result = g_key_file_to_data(kf, NULL, NULL);
	g_key_file_free(kf);
	return result;
}

struct vys_configuration *
init_from_key_file(GKeyFile *kf)
{
	struct vys_configuration config;

	gchar *mc_addr = g_key_file_get_string(
		kf, VYS_CONFIG_GROUP_NAME, SIGNAL_MULTICAST_ADDRESS_KEY, NULL);
	g_assert(mc_addr != NULL);
	gsize mc_addr_len =
		g_strlcpy(config.signal_multicast_address, mc_addr,
		          sizeof(config.signal_multicast_address));
	g_free(mc_addr);
	/* check that value is not too long */
	if (mc_addr_len >= sizeof(config.signal_multicast_address))
		return NULL;

	return g_memdup(&config, sizeof(config));
}

struct vys_configuration *
vys_configuration_new(const char *path)
{
	struct vys_configuration *result = NULL;
	gchar *dcfg = default_config();
	gchar *fcfg = load_config(VYS_CONFIG_PATH, NULL);
	GError *error = NULL;
	gchar *pcfg = load_config(path, &error);
	if (error == NULL) {
		gchar *cfg = g_strjoin("\n", dcfg, fcfg, pcfg, NULL);
		GKeyFile *kf = g_key_file_new();
		if (g_key_file_load_from_data(kf, cfg, -1, G_KEY_FILE_NONE, NULL))
			result = init_from_key_file(kf);
		g_key_file_free(kf);
		g_free(cfg);
	}
	return result;
}

void
vys_configuration_free(struct vys_configuration *config)
{
	g_free(config);
}
