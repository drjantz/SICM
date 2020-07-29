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

void profile_rss_arena_init(profile_rss_info *);
void profile_rss_deinit();
void profile_rss_init();
void *profile_rss(void *);
void profile_rss_interval(int);
void profile_rss_skip_interval(int);
void profile_rss_post_interval(arena_profile *);

void profile_rss_arena_init(profile_rss_info *info) {
  info->peak = 0;
  info->current = 0;
}

void profile_rss_deinit() {
  close(prof.profile_rss.pagemap_fd);
}

void profile_rss_init() {
  prof.profile_rss.pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
  if (prof.profile_rss.pagemap_fd < 0) {
    fprintf(stderr, "Failed to open /proc/self/pagemap. Aborting.\n");
    exit(1);
  }
  prof.profile_rss.pfndata = NULL;
  prof.profile_rss.addrsize = sizeof(uint64_t);
  prof.profile_rss.pagesize = (size_t) sysconf(_SC_PAGESIZE);
  prof.profile_rss.bailout = 0;
}

void *profile_rss(void *a) {
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

  while(1) { }
}

/* Just copies the previous value */
void profile_rss_skip_interval(int s) {
  end_interval();
}

void profile_rss_interval(int s) {
  size_t i, n, numpages;
  unsigned long long prof_rate;
  uint64_t start, end;
  arena_info *arena;
  ssize_t num_read;
  arena_profile *aprof;
  struct timespec start_time, end_time, elapsed_time, target_time;

  if (prof.profile_rss.bailout) {
    prof.profile_rss.bailout = 0;
    return;
  }

  clock_gettime(CLOCK_MONOTONIC, &start_time);

  /* Grab the lock for the extents array */
  pthread_rwlock_rdlock(&tracker.extents_lock);

  /* Iterate over the chunks */
  extent_arr_for(tracker.extents, i) {
    start = (uint64_t) tracker.extents->arr[i].start;
    end = (uint64_t) tracker.extents->arr[i].end;
    arena = (arena_info *) tracker.extents->arr[i].arena;
    if(!arena) continue;
    aprof = prof.profile->arenas[arena->index];
    if(!aprof) continue;

    numpages = (end - start) / prof.profile_rss.pagesize;
    prof.profile_rss.pfndata = (union pfn_t *) orig_realloc(prof.profile_rss.pfndata, numpages * prof.profile_rss.addrsize);

    /* Seek to the starting of this chunk in the pagemap */
    if(lseek64(prof.profile_rss.pagemap_fd, (start / prof.profile_rss.pagesize) * prof.profile_rss.addrsize, SEEK_SET) == ((__off64_t) - 1)) {
      close(prof.profile_rss.pagemap_fd);
      fprintf(stderr, "Failed to seek in the PageMap file. Aborting.\n");
      exit(1);
    }

    /* Read in all of the pfns for this chunk */
    num_read = read(prof.profile_rss.pagemap_fd, prof.profile_rss.pfndata, prof.profile_rss.addrsize * numpages);
    if(num_read == -1) {
      fprintf(stderr, "Failed to read from PageMap file. Aborting: %d, %s\n", errno, strerror(errno));
      exit(1);
    } else if(num_read < prof.profile_rss.addrsize * numpages) {
      printf("WARNING: Read less bytes than expected.\n");
      continue;
    }

    /* Iterate over them and check them, sum up RSS in arena->rss */
    for(n = 0; n < numpages; n++) {
      if(!(prof.profile_rss.pfndata[n].obj.present)) {
        continue;
      }
      aprof->profile_rss.current += prof.profile_rss.pagesize;
    }
  }

  pthread_rwlock_unlock(&tracker.extents_lock);

  clock_gettime(CLOCK_MONOTONIC, &end_time);
  timespec_diff(&start_time, &end_time, &elapsed_time);
  prof_rate = (profopts.profile_rate_nseconds * profopts.profile_rss_skip_intervals);
  target_time.tv_sec = prof_rate / 1000000000;
  target_time.tv_nsec = prof_rate % 1000000000;
  if (timespec_cmp(&target_time, &elapsed_time) != 0) {
    prof.profile_rss.bailout = 1;
  }

  end_interval();
}

void profile_rss_post_interval(arena_profile *info) {
  profile_rss_info *aprof;

  aprof = &(info->profile_rss);

  /* Maintain the peak for this arena */
  if(aprof->current > aprof->peak) {
    aprof->peak = aprof->current;
  }
  aprof->current = 0;
}
