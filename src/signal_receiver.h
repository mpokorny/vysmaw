/* -*- mode: c; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
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
#ifndef SIGNAL_RECEIVER_H_
#define SIGNAL_RECEIVER_H_

#include <vys_buffer_pool.h>
#include <vysmaw_private.h>

struct signal_receiver_context {
  vysmaw_handle handle;

  GAsyncQueue *signal_msg_queue;

  int loop_fd;
};

void *signal_receiver(struct signal_receiver_context *context);

#endif /* SIGNAL_RECEIVER_H_ */
