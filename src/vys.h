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

#define VYS_MULTICAST_ADDRESS_SIZE 32
#define VYS_DATA_DIGEST_SIZE 16

struct vys_configuration {
	/* multicast address for signal messages; expected format is dotted quad IP
	 * address string */
	char signal_multicast_address[VYS_MULTICAST_ADDRESS_SIZE];
};

extern struct vys_configuration *vys_configuration_new(const char *path)
	__attribute__((malloc));
extern void vys_configuration_free(struct vys_configuration *config)
	__attribute__((nonnull));

#ifdef __cplusplus
}
#endif
	
#endif /* VYS_H_ */
