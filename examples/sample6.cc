/* -*- mode: c++; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
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
#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <complex.h>
#include <csignal>
#include <ctime>
#include <fstream>
#include <ios>
#include <iostream>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>

#include <unistd.h>
#include <vysmaw.h>

// max time to wait for message on queue
#define QUEUE_TIMEOUT_MICROSEC 100000

using namespace std;

struct sp {
  uint64_t timestamp;
  uint8_t stations[2];
  uint8_t baseband_index;
  uint8_t spectral_window_index;
  uint8_t polarization_product_id;
  float f[]; // for alignment
};

namespace std {
// default_delete specialization for struct vysmaw_message
template <> struct default_delete<struct vysmaw_message> {
  void operator()(struct vysmaw_message *msg) {
    vysmaw_message_unref(msg);
  }
};

// default_delete specialization for struct vysmaw_configuration
template <> struct default_delete<struct vysmaw_configuration> {
  void operator()(struct vysmaw_configuration *conf) {
    vysmaw_configuration_free(conf);
  }
};
}

// a filter that accepts everything
void
filter(const char *config_id, const uint8_t stations[2],
       uint8_t baseband_index, uint8_t baseband_id,
       uint8_t spectral_window_index, uint8_t polarization_product_id,
       const struct vys_spectrum_info *infos, uint8_t num_infos,
       void *user_data, bool *pass_filter)
{
  unsigned *num_cb = reinterpret_cast<unsigned *>(user_data);
  unsigned num_procs = reinterpret_cast<unsigned *>(user_data)[1];
  unsigned proc_idx = reinterpret_cast<unsigned *>(user_data)[2];
  *num_cb += 1;
  //for (auto i = 0; i < num_infos; ++i)
  //  *pass_filter++ = true;
  for (auto i = 0; i < num_infos; ++i) {
    // This should select 1 out of every N seconds to receive
    uint64_t isec = infos[i].timestamp / 1000000000L;
    if ((isec % num_procs) == proc_idx) 
      *pass_filter++ = true;
    else
      *pass_filter++ = false;
  }
}

// handle sigint for user exit condition
sig_atomic_t sigint_occurred = false;
void sigint_handler(int p)
{
  sigint_occurred = true;
}

// get a message from a message queue, with a timeout to support user interrupt
// handling
unique_ptr<struct vysmaw_message>
pop(vysmaw_message_queue q)
{
  return unique_ptr<struct vysmaw_message>(
    vysmaw_message_queue_timeout_pop(q, QUEUE_TIMEOUT_MICROSEC));
}

// display counts of messages
void
show_counters(array<unsigned,VYSMAW_MESSAGE_END + 1> &counters)
{
  const unordered_map<enum vysmaw_message_type,string> names = {
    {VYSMAW_MESSAGE_SPECTRA, "spectra-message"},
    {VYSMAW_MESSAGE_QUEUE_ALERT, "message-queue-alert"},
    {VYSMAW_MESSAGE_SPECTRUM_BUFFER_STARVATION, "data-buffer-starvation"},
    {VYSMAW_MESSAGE_SIGNAL_RECEIVE_FAILURE, "signal-receive-failure"},
    {VYSMAW_MESSAGE_VERSION_MISMATCH, "vys-version-mismatch"},
    {VYSMAW_MESSAGE_SIGNAL_RECEIVE_QUEUE_UNDERFLOW, "signal-receive-queue-underflow"},
    {VYSMAW_MESSAGE_END, "end"},
  };

  size_t max_name_len = 0;
  for (auto&& n : names)
    max_name_len = max(n.second.length(), max_name_len);

  const enum vysmaw_message_type msg_types[] = {
    VYSMAW_MESSAGE_SPECTRA,
    VYSMAW_MESSAGE_QUEUE_ALERT,
    VYSMAW_MESSAGE_SPECTRUM_BUFFER_STARVATION,
    VYSMAW_MESSAGE_SIGNAL_RECEIVE_QUEUE_UNDERFLOW,
    VYSMAW_MESSAGE_SIGNAL_RECEIVE_FAILURE,
    VYSMAW_MESSAGE_VERSION_MISMATCH,
    VYSMAW_MESSAGE_END
  };

  for (auto&& m : msg_types) {
    cout.width(max_name_len);
    cout << right << names.at(m);
    cout << ": " << counters[m] << endl;
  }
}

template <typename A>
string
elements(const set<A> &s)
{
  stringstream result;
  for (auto &&a : s)
    result << to_string(a) << " ";
  return result.str();
}

int
main(int argc, char *argv[])
{
  unique_ptr<struct vysmaw_configuration> config;

  typedef chrono::duration<long,milli> ms;
  ms duration = chrono::duration<long,milli>::max();
  unique_ptr<ofstream> binary_output;
  decltype(cout.rdbuf()) coutbuf = cout.rdbuf();
  ios::sync_with_stdio(false);
  unsigned num_procs=1, proc_idx=0;

  // initialize vysmaw configuration
  stringstream usage;
  usage << "usage: "
        << argv[0]
        << " [config] [output file ('-' for text stdout)]"
        << endl;
  switch (argc) {
  case 5:
      num_procs = atoi(argv[3]);
      proc_idx = atoi(argv[4]);
  case 3:
    config.reset(vysmaw_configuration_new(argv[1]));
    if (string(argv[2]) != "-") {
      binary_output.reset(
        new ofstream(argv[2], ios::out | ios::binary | ios::trunc));
      coutbuf = cout.rdbuf(binary_output->rdbuf());
    }
    break;
  default:
    cerr << usage.str();
    return -1;
  }

  // one consumer, using filter()
  unsigned filter_data[3];
  //unsigned num_cb = 0;
  filter_data[0] = 0;
  filter_data[1] = num_procs;
  filter_data[2] = proc_idx;
  struct vysmaw_consumer consumer = {
    .filter = filter,
    //.filter_data = &num_cb
    .filter_data = filter_data
  };

  // this application keeps count of the message types it receives
  array<unsigned,VYSMAW_MESSAGE_END + 1> counters;
  counters.fill(0);
  unsigned num_valid_spectra = 0;
  unsigned reset_count=0, num_reset=0;

  // catch SIGINT to exit gracefully
  bool interrupted = false;
  signal(SIGINT, sigint_handler);

  // a variety of summary accumulators
  unsigned num_alerts = 0;
  unsigned num_spectrum_buffers_unavailable = 0;
  unsigned num_signal_buffers_unavailable = 0;
  unsigned num_spectra_mismatched_version = 0;
  unsigned num_verification_failures = 0;
  set<string> signal_receive_status;
  set<string> rdma_read_status;
  
  // take messages until a VYSMAW_MESSAGE_END appears
  auto t0 = chrono::system_clock::now();

  // start vysmaw client
  
  vysmaw_handle handle = vysmaw_start(config.get(), &consumer);
  unique_ptr<struct vysmaw_message> message = move(pop(consumer.queue));
  while ((!message || message->typ != VYSMAW_MESSAGE_END)) {
    // start shutdown if requested by user
    if (sigint_occurred && !interrupted) {
      if (handle) vysmaw_shutdown(handle);
      handle = nullptr;
      interrupted = true;
    }
    // record message type and accumulate summary information
    assert(!message || message->typ < VYSMAW_MESSAGE_END);
    if (message) {
      ++counters[message->typ];
      switch (message->typ) {
      case VYSMAW_MESSAGE_SPECTRA: {
        for (unsigned i = 0; i < message->content.spectra.num_spectra; ++i) {
          if (message->data[i].failed_verification) {
            ++num_verification_failures;
          } else if (message->data[i].rdma_read_status[0] != '\0') {
            rdma_read_status.insert(message->data[i].rdma_read_status);
          } else {
            _Complex float* values = message->data[i].values;
            if (values != NULL) {
              ++num_valid_spectra;
              ++reset_count;
              struct vysmaw_data_info* info = &(message->content.spectra.info);
              struct sp sp = {
                .timestamp = message->data[i].timestamp,
                .stations = {info->stations[0], info->stations[1]},
                .baseband_index = info->baseband_index,
                .spectral_window_index = info->spectral_window_index,
                .polarization_product_id = info->polarization_product_id
              };
              if (!binary_output) {
                for (unsigned b = 0; b < info->num_bins; ++b) {
                  cout << std::to_string(sp.timestamp)
                       << " " << std::to_string(sp.stations[0])
                       << " " << std::to_string(sp.stations[1])
                       << " " << std::to_string(sp.baseband_index)
                       << " " << std::to_string(sp.spectral_window_index)
                       << " " << std::to_string(sp.polarization_product_id)
                       << " ";
                  for (unsigned c = 0; c < info->num_channels; ++c)
                    cout << creal(values[c]) << " " << cimag(values[c]) << " ";
                  cout << endl;
                  values += info->bin_stride;
                }
              } else {
                for (unsigned b = 0; b < info->num_bins; ++b) {
                  bool do_write=false;
                  for (unsigned ic=0; ic<info->num_channels; ++ic) {
                      if (isnan(creal(values[ic])) || isnan(cimag(values[ic])) 
                              || fabs(creal(values[ic]))>1e20 || fabs(cimag(values[ic]))>1e20) 
                          do_write=true;
                  }
                  if (do_write) {
                      // write header
                      cout.write(reinterpret_cast<char *>(&sp), sizeof(sp));
                      // write data
                      //cout.write(
                      //  reinterpret_cast<char *>(values),
                      //  info->num_channels * sizeof(values[0]));
                      values += info->bin_stride;
                  }
                }
              }
            }
          }
        }
        break;
      }
      case VYSMAW_MESSAGE_QUEUE_ALERT:
        ++num_alerts;
        break;
      case VYSMAW_MESSAGE_SPECTRUM_BUFFER_STARVATION:
        num_spectrum_buffers_unavailable +=
          message->content.num_spectrum_buffers_unavailable;
        break;
      case VYSMAW_MESSAGE_VERSION_MISMATCH:
        num_spectra_mismatched_version +=
          message->content.num_spectra_mismatched_version;
        break;
      case VYSMAW_MESSAGE_SIGNAL_RECEIVE_FAILURE:
        signal_receive_status.insert(
          message->content.signal_receive_status);
        break;
      default:
        break;
      }
    }

    // Restart consumer sometimes
    if (reset_count > 4000000) {
    //if (reset_count > 2000000) {
    //if (reset_count > 8000) {
      cerr << endl;
      cerr << "--------------- going to reset consumer (" << num_reset << ")" << endl;
      cerr.flush();
      if (handle) vysmaw_shutdown(handle);
      cerr << "                called shutdown" << endl;
      cerr.flush();
      // Flush out message queue
      while (message->typ != VYSMAW_MESSAGE_END) {
          do { message=move(pop(consumer.queue)); } while (!message);
      }
      message.reset(); // free memory for final message
      cerr << "                flushed queue" << endl;
      cerr.flush();
      sleep(3);
      cerr << "                slept" << endl;
      cerr.flush();
      handle = vysmaw_start(config.get(), &consumer);
      assert(handle);
      cerr << "                restarted" << endl;
      cerr << endl;
      cerr.flush();
      num_reset++;
      reset_count = 0;
    } 

    // get next message
    message = move(pop(consumer.queue));
  }
  if (message) ++counters[message->typ];
  auto t1 = chrono::system_clock::now();

  if (binary_output) {
    binary_output.reset();
    cout.rdbuf(coutbuf);
  }

  // display counts of received messages
  if (interrupted) cout << endl;
  show_counters(counters);

  // display message for end condition
  if (message) {
    switch (message->content.result.code) {
    case vysmaw_result::VYSMAW_NO_ERROR:
      cout << "ended without error" << endl;
      break;

    case vysmaw_result::VYSMAW_SYSERR:
      cout << "ended with errors" << endl
           << message->content.result.syserr_desc;
      break;

    case vysmaw_result::VYSMAW_ERROR_BUFFPOOL:
      cout << "ended with fatal 'buffpool' error" << endl;
      break;

    default:
      break;
    }
  }

  // performance summary
  auto span =
    chrono::duration_cast<chrono::duration<double> >(t1 - t0);
  cout << to_string(filter_data[0])
       << " callbacks and "
       << to_string(num_valid_spectra)
       << " valid spectra in "
       << span.count()
       << " seconds ("
       << (num_valid_spectra / span.count())
       << " valid spectra per sec)"
       << endl;

  // error summary...only when it's interesting
  if (num_verification_failures > 0)
    cout << "num verify errors : "
         << num_verification_failures << endl;
  if (num_alerts > 0)
    cout << "num queue alerts  : "
         << num_alerts << endl;
  if (num_spectrum_buffers_unavailable > 0)
    cout << "num data buff miss: "
         << num_spectrum_buffers_unavailable << endl;
  if (num_signal_buffers_unavailable > 0)
    cout << "num sig buff miss : "
         << num_signal_buffers_unavailable << endl;
  if (num_spectra_mismatched_version > 0)
    cout << "num vsn mismatch  : "
         << num_spectra_mismatched_version << endl;
  if (!signal_receive_status.empty()) {
    cout << "signal rcv errs   :";
    for (auto&& s : signal_receive_status)
      cout << endl << " - " << s;
    cout << endl;
  }
  if (!rdma_read_status.empty()) {
    cout << "rdma read errs    :";
    for (auto&& s : rdma_read_status)
      cout << endl << " - " << s;
    cout << endl;
  }

  // release the last message and shut down the library if it hasn't already
  // been done
  if (message) message.reset();
  if (handle) vysmaw_shutdown(handle);

  return 0;
}

