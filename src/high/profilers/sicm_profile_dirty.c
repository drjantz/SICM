#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sys/types.h>


#define SICM_RUNTIME 1
#include "sicm_runtime.h"
#include "sicm_profilers.h"
#include "sicm_profile.h"

void profile_dirty_deinit();
void profile_dirty_init();
void *profile_dirty(void *);
void profile_dirty_interval(int);
void profile_dirty_skip_interval(int);
void profile_dirty_post_interval();

/* MRJ -- 07/29/20 -- I updated this code to incorporate Ben's changes from
 * the beginning of the summer and I did not test it. This code is likely
 * broken.
 */

void profile_dirty_deinit() {
  close(prof.profile_dirty.pagemap_fd);
  fclose(profopts.dirty_profile_output_file);
}

void clear_refs() {
  int clear_refs_fd;
  const char four_buf[2] = "4";

  clear_refs_fd = open("/proc/self/clear_refs", O_WRONLY);
  if (clear_refs_fd < 0) {
    fprintf(stderr, "Failed to open /proc/self/pagemap. Aborting.\n");
    exit(1);
  }
  write(clear_refs_fd, four_buf, 2); 
  close(clear_refs_fd);
}

void profile_dirty_init() {
  prof.profile_dirty.pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
  if (prof.profile_dirty.pagemap_fd < 0) {
    fprintf(stderr, "Failed to open /proc/self/pagemap. Aborting.\n");
    exit(1);
  }
  prof.profile_dirty.pfndata = NULL;
  prof.profile_dirty.addrsize = sizeof(uint64_t);
  prof.profile_dirty.pagesize = (size_t) sysconf(_SC_PAGESIZE);
  prof.profile_dirty.cur_val = 0;
  prof.profile_dirty.dirty_page_map = tree_make(addr_t, dirty_profile_ptr);
  clear_refs();
  prof.profile_dirty.bailout = 0;
  clock_gettime(CLOCK_MONOTONIC, &(prof.profile_dirty.start_time));
  clock_gettime(CLOCK_MONOTONIC, &(prof.profile_dirty.prev_time));
}

void *profile_dirty(void *a) {
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

  while(1) { }
}

/* Just copies the previous value */
void profile_dirty_skip_interval(int s) {
}

void profile_dirty_interval(int s) {
  size_t i, n, numpages, pg_off, new;
  uint64_t start, end;
  ssize_t num_read;
  struct timespec cur_time, elapsed_time, target_time;
  addr_t addr;
  dirty_profile_ptr dirty_rec;
  tree_it(addr_t, dirty_profile_ptr) it;

  clock_gettime(CLOCK_MONOTONIC, &cur_time);
  timespec_diff(&(prof.profile_dirty.prev_time), &cur_time, &elapsed_time);
  target_time.tv_sec = profopts.profile_rate_nseconds / 1000000000;
  target_time.tv_nsec = profopts.profile_rate_nseconds % 1000000000;
  if (timespec_cmp(&target_time, &elapsed_time) == 0) {
    prof.profile_dirty.bailout = 1;
    return;
  }

#if 0
  fprintf(profopts.dirty_profile_output_file, "val:  %-6d%11d.%03ld\n",
    prof.profile_dirty.cur_val, (long long)elapsed_time.tv_sec,
    (elapsed_time.tv_nsec / (1000000)));
#endif

  /* Grab the lock for the extents array */
  pthread_rwlock_rdlock(&tracker.extents_lock);

  /* Iterate over the chunks */
  extent_arr_for(tracker.extents, i) {
    start = (uint64_t) tracker.extents->arr[i].start;
    end = (uint64_t) tracker.extents->arr[i].end;

    numpages = (end - start) / prof.profile_dirty.pagesize;
    prof.profile_dirty.pfndata = (union pfn_t *) orig_realloc(
      prof.profile_dirty.pfndata, numpages * prof.profile_dirty.addrsize);

    /* Seek to the starting of this chunk in the pagemap */
    if(lseek64( prof.profile_dirty.pagemap_fd,
               ((start / prof.profile_dirty.pagesize) * 
                 prof.profile_dirty.addrsize),
               SEEK_SET ) == ((__off64_t) - 1)) {
      close(prof.profile_dirty.pagemap_fd);
      fprintf(stderr, "Failed to seek in the PageMap file. Aborting.\n");
      exit(1);
    }

    /* Read in all of the pfns for this chunk */
    num_read = read(prof.profile_dirty.pagemap_fd,
                    prof.profile_dirty.pfndata,
                    prof.profile_dirty.addrsize * numpages);
    if(num_read == -1) {
      fprintf(stderr, "Failed to read from PageMap file. Aborting: %d, %s\n", errno, strerror(errno));
      exit(1);
    } else if(num_read < prof.profile_dirty.addrsize * numpages) {
      printf("WARNING: Read less bytes than expected.\n");
      continue;
    }

    /* Record the dirty pages */
    for(n = 0, pg_off = 0; n < numpages; n++, (pg_off += (1<<PAGE_SHIFT))) {
      if(!(prof.profile_dirty.pfndata[n].obj.present)) {
        continue;
      }

      //addr = (addr_t) ( PAGE_ADDR(start + pg_off) );
      addr = (addr_t) ( (((uint64_t)prof.profile_dirty.pfndata[n].obj.pfn)<<9) &
                        ((uint64_t)0xfffffffffffffe00) );
      it = tree_lookup( prof.profile_dirty.dirty_page_map, addr );
      if (!(tree_it_good(it))) {
        dirty_rec = (dirty_profile_ptr) orig_malloc(sizeof(dirty_profile));
        if (dirty_rec == NULL) {
          fprintf(stderr, "profile_dirty: out of memory\n");
          exit(-ENOMEM);
        }
        dirty_rec->last_dirty_val = prof.profile_dirty.cur_val;
        tree_insert(prof.profile_dirty.dirty_page_map, addr, dirty_rec);
        new = 1;
      } else {
        dirty_rec = tree_it_val(it);
        new = 0;
      }

      dirty_rec->live = 1;
      if (prof.profile_dirty.pfndata[n].obj.soft_dirty) {
        dirty_rec->last_dirty_val = prof.profile_dirty.cur_val;
      }
    }
  }
  pthread_rwlock_unlock(&tracker.extents_lock);

  clock_gettime(CLOCK_MONOTONIC, &(prof.profile_dirty.prev_time));
}

void profile_dirty_post_interval() {
  tree_it(addr_t, dirty_profile_ptr) it;
  dirty_profile_ptr dpp;
  struct timespec cur_time, elapsed_time;
  uint64_t cur_live, clean[3];

  if (prof.profile_dirty.bailout) {
    prof.profile_dirty.bailout = 0;
    return;
  }

  cur_live = 0;
  memset(clean, 0, sizeof(uint64_t)*3);
  tree_traverse (prof.profile_dirty.dirty_page_map, it) {
    dpp = tree_it_val(it);
    if (dpp->live) {
      cur_live++;
      if (prof.profile_dirty.cur_val > 0) {
        if (dpp->last_dirty_val < prof.profile_dirty.cur_val) {
          clean[0]++;
        }
        if (prof.profile_dirty.cur_val > 9) {
          if (dpp->last_dirty_val < (prof.profile_dirty.cur_val-9)) {
            clean[1]++;
          }
          if (prof.profile_dirty.cur_val > 99) {
            if (dpp->last_dirty_val < (prof.profile_dirty.cur_val-99)) {
              clean[2]++;
            }
          }
        }
      }
    }
    dpp->live = 0;
  }

  clock_gettime(CLOCK_MONOTONIC, &cur_time);
  timespec_diff(&(prof.profile_dirty.start_time), &cur_time, &elapsed_time);

  if (prof.profile_dirty.cur_val == 0) {
    fprintf(profopts.dirty_profile_output_file, "%-6s%15s%20s%20s%20s%20s\n",
      "val", "time", "live", "1-clean", "10-clean", "100-clean");
  }

  fprintf(profopts.dirty_profile_output_file, "%-6d%11d.%03ld%20lu",
    prof.profile_dirty.cur_val, (long long)elapsed_time.tv_sec,
    (elapsed_time.tv_nsec / (1000000)), cur_live);

  if (prof.profile_dirty.cur_val > 0) {
    fprintf(profopts.dirty_profile_output_file, "%20lu", clean[0]);
  } else {
    fprintf(profopts.dirty_profile_output_file, "%20s", "-");
  }

  if (prof.profile_dirty.cur_val > 9) {
    fprintf(profopts.dirty_profile_output_file, "%20lu", clean[1]);
  } else {
    fprintf(profopts.dirty_profile_output_file, "%20s", "-");
  }

  if (prof.profile_dirty.cur_val > 99) {
    fprintf(profopts.dirty_profile_output_file, "%20lu", clean[2]);
  } else {
    fprintf(profopts.dirty_profile_output_file, "%20s", "-");
  }
  fprintf(profopts.dirty_profile_output_file, "\n");
  fflush(profopts.dirty_profile_output_file);

  prof.profile_dirty.cur_val++;
  clear_refs();
}
