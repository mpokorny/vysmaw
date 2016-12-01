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

static gboolean
load_config(GKeyFile *keyfile, const gchar *path)
{
	GError *error = NULL;
	gboolean result =
		g_key_file_load_from_file(keyfile, path, G_KEY_FILE_NONE, &error);
	if (!result) {
		fprintf(stderr, "Failed to load vys config file '%s': %s\n",
		        path, error->message);
		g_error_free(error);
	}
	return result;
}

struct vys_configuration *
vys_configuration_new(const char *path)
{
	struct vys_configuration *result = g_new(struct vys_configuration, 1);
	/* initialize with defaults */
	g_strlcpy(result->signal_multicast_address,
	          VYS_SIGNAL_MULTICAST_ADDRESS,
	          sizeof(result->signal_multicast_address));

	/* Override defaults with values from configuration file.*/
	GKeyFile *keyfile = g_key_file_new();
	if (load_config(keyfile, (path != NULL) ? path : VYS_CONFIG_PATH)) {
		/* get values from config file */
		GError *error = NULL;
		/* signal_multicast_address */
		gchar *mc_addr = g_key_file_get_string(
			keyfile, VYS_CONFIG_GROUP_NAME, "signal_multicast_address", &error);
		if (mc_addr != NULL) {
			/* check that value from file is not too long */
			if (strlen(mc_addr) < sizeof(result->signal_multicast_address))
				g_strlcpy(result->signal_multicast_address, mc_addr,
				          sizeof(result->signal_multicast_address));
			else
				fprintf(stderr, "%s",
				        "Configuration value too long - using default value\n");
			g_free(mc_addr);
		} else {
			fprintf(stderr,
			        "Failed to read configuration parameter: %s - "
			        "using default value\n",
			        error->message);
			g_error_free(error);
		}
	}
	return result;
}

void
vys_configuration_free(struct vys_configuration *config)
{
	g_free(config);
}
