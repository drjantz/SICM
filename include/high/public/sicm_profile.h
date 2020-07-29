#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <asm/perf_regs.h>
#include <asm/unistd.h>
#include <time.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include <errno.h>
#include <poll.h>

#include "sicm_runtime.h"
#include "sicm_profilers.h"
#include "sicm_tree.h"

#define PAGE_SHIFT 12
#define CACHE_BLOCK_SHIFT 6
#define PAGE_ADDR(addr) ((intptr_t) (((intptr_t)addr) >> PAGE_SHIFT))
#define CACHE_BLOCK_ADDR(addr) ((intptr_t) (((intptr_t)addr) >> CACHE_BLOCK_SHIFT))
#define PFN_INVALID 1ull

/* Profiling information for one arena */
typedef struct arena_profile {
  unsigned index;
  int num_alloc_sites, *alloc_sites;

  profile_all_info profile_all;
  profile_rss_info profile_rss;
  profile_extent_size_info profile_extent_size;
  profile_allocs_info profile_allocs;
  profile_online_info profile_online;
} arena_profile;

typedef struct region_profile {
  size_t num_alloc_sites;
  int *alloc_sites;
  profile_all_info rprof;
  uint64_t pfn;
} region_profile;
typedef region_profile * region_profile_ptr;

#ifndef SICM_PROFILE /* Make sure we don't define the below trees twice */
#define SICM_PROFILE
use_tree(addr_t, region_profile_ptr);
use_tree(region_profile_ptr, addr_t);

void profile_all_post_interval_region_map( tree(addr_t, region_profile_ptr) );
void timespec_diff(struct timespec *start, struct timespec *stop,
                   struct timespec *result);
char timespec_cmp(struct timespec *a, struct timespec *b);
#endif

typedef struct interval_profile {
  /* Array of arenas and their info */
  size_t num_arenas;
  arena_profile **arenas;
  tree(addr_t, region_profile_ptr) page_map;
  tree(addr_t, region_profile_ptr) cache_block_map;
} interval_profile;

/* Profiling information for a whole application */
typedef struct application_profile {
  size_t num_intervals, num_profile_all_events,
         num_arenas;

  size_t upper_capacity, lower_capacity;

  /* the last interval's page_map and cache_block_map */
  tree(addr_t, region_profile_ptr) page_map;
  tree(addr_t, region_profile_ptr) cache_block_map;

  /* Array of the last interval's arenas */
  arena_profile **arenas;

  /* Array of event strings in the profiling */
  char **profile_all_events;

  interval_profile *intervals;
} application_profile;

/* Information about a single profiling thread. Used by the
 * master profiling thread to keep track of them. */
typedef struct profile_thread {
  pthread_t id;
  int signal, skip_signal;
  unsigned long skip_intervals; /* Number of intervals we should skip */
  unsigned long skipped_intervals; /* Number of intervals we have skipped */
  void (*interval_func)(int); /* Per-interval function */
  void (*skip_interval_func)(int); /* Per-interval skip function */
} profile_thread;

typedef struct profiler {
  /* For the master thread */
  pthread_t master_id;
  timer_t timerid;

  /* One for each profiling thread */
  profile_thread *profile_threads;
  size_t num_profile_threads;

  /* Convenience pointers */
  interval_profile *cur_interval, *prev_interval;

  /* Sync the threads */
  pthread_mutex_t mtx;
  pthread_cond_t cond;
  char threads_finished;

  /* For the main application thread to
   * signal the master to stop
   */
  int stop_signal, master_signal;

  /* Profiling information for the currently-running application */
  application_profile *profile;
  pthread_rwlock_t profile_lock;

  /* Data for each profile thread */
  profile_all_data profile_all;
  profile_rss_data profile_rss;
  profile_extent_size_data profile_extent_size;
  profile_allocs_data profile_allocs;
  profile_online_data profile_online;
  profile_dirty_data profile_dirty;

  profile_all_info val_prof;
} profiler;

extern profiler prof;

void sh_start_profile_master_thread();
void sh_stop_profile_master_thread();

void end_interval();

void create_arena_profile(int, int);
void add_site_profile(int, int);

static inline void copy_arena_profile(arena_profile *dst, arena_profile *src) {
  memcpy(dst, src, sizeof(arena_profile));
  dst->alloc_sites = orig_malloc(sizeof(int) * dst->num_alloc_sites);
  memcpy(dst->alloc_sites, src->alloc_sites, sizeof(int) * dst->num_alloc_sites);
  dst->profile_all.events = orig_malloc(sizeof(per_event_profile_all_info) * prof.profile->num_profile_all_events);
  memcpy(dst->profile_all.events, src->profile_all.events, sizeof(per_event_profile_all_info) * prof.profile->num_profile_all_events);
}

static inline void copy_region_map( 
  tree(addr_t, region_profile_ptr) dst,
  tree(addr_t, region_profile_ptr) src )
{
  region_profile_ptr src_rec, dst_rec;
  tree_it(addr_t, region_profile_ptr) it;
 
  tree_traverse(src, it) {
    src_rec = tree_it_val(it);
    dst_rec = (region_profile_ptr) orig_malloc(sizeof(region_profile));
    if (dst_rec == NULL) {
      printf("copy_region_map: out of memory\n");
      exit(-ENOMEM);
    }

    dst_rec->rprof.events = orig_malloc(sizeof(per_event_profile_all_info) * prof.profile->num_profile_all_events);
    if (dst_rec->rprof.events == NULL) {
      printf("copy_region_map: out of memory\n");
      exit(-ENOMEM);
    }

    memcpy(dst_rec->rprof.events, src_rec->rprof.events, sizeof(per_event_profile_all_info) * prof.profile->num_profile_all_events);
    tree_insert(dst, tree_it_key(it), dst_rec);
  }
}

static inline uint64_t_ptr get_new_site_profile() {
  size_t i;
  uint64_t_ptr rec;

  rec = (uint64_t_ptr) orig_malloc( sizeof(uint64_t) *
        (prof.profile->num_profile_all_events + 2) );
  if (rec == NULL) {
    printf("site_profile: out of memory\n");
    exit(-ENOMEM);
  }

  for (i = 0; i < (prof.profile->num_profile_all_events+2); i++) {
    rec[i] = 0ull;
  }

  return rec;
}

static inline region_profile_ptr get_new_region_profile() {
  size_t i;
  region_profile_ptr rp;

  rp = (region_profile_ptr) orig_malloc(sizeof(region_profile));
  if (rp == NULL) {
    printf("region_profile: out of memory\n");
    exit(-ENOMEM);
  }

  rp->rprof.events = orig_malloc(sizeof(per_event_profile_all_info) * prof.profile->num_profile_all_events);
  if (rp->rprof.events == NULL) {
    printf("region_profile: out of memory\n");
    exit(-ENOMEM);
  }

  for (i = 0; i < prof.profile->num_profile_all_events; i++) {
    rp->rprof.events[i].current = 0;
    rp->rprof.events[i].peak    = 0;
    rp->rprof.events[i].total   = 0;
  }

  rp->alloc_sites = NULL;
  rp->num_alloc_sites = 0;
  rp->pfn = PFN_INVALID;
  return rp;
}

static inline void reset_region_map( tree(addr_t, region_profile_ptr) map)
{
  region_profile_ptr rec;
  tree_it(addr_t, region_profile_ptr) it;
 
  tree_traverse(map, it) {
    rec = tree_it_val(it);
    for (unsigned i = 0; i < prof.profile->num_profile_all_events; i++) {
      rec->rprof.events[i].current = 0;
      rec->rprof.events[i].peak    = 0;
      rec->rprof.events[i].total   = 0;
    }
  }
}

static uint64_t_ptr get_site_rec(tree(int, uint64_t_ptr) site_profile, int cur_site) {
  tree_it(int, uint64_t_ptr) it;
  uint64_t_ptr site_rec;
  size_t i;

  it = tree_lookup(site_profile, cur_site);
  if (!(tree_it_good(it))) {
    site_rec = orig_malloc(sizeof(uint64_t)*(prof.profile->num_profile_all_events+2));
    if (site_rec == NULL) {
      fprintf(stderr, "sh_print_profiling: out of memory\n");
      exit(-ENOMEM);
    }
    for (i = 0; i < (prof.profile->num_profile_all_events+2); i++) {
      site_rec[i] = 0ull;
    }
    tree_insert(site_profile, cur_site, site_rec);
  } else {
    site_rec = tree_it_val(it);
  }
  return site_rec;
}


#define prof_check_good(a, p, i) \
  a = tracker.arenas[i]; \
  p = prof.profile->arenas[i]; \
  if((!a) || (!p)) continue;

#define get_arena_prof(i) \
  prof.profile->arenas[i]

#define get_arena_online_prof(i) \
  (&(get_arena_prof(i)->profile_online))

#define get_arena_all_prof(i) \
  (&(get_arena_prof(i)->profile_all))

/* Since the profiling library stores an interval after it happens,
   the "previous interval" is actually the last one recorded */
#define get_prev_arena_prof(i) \
  prof.cur_interval->arenas[i]

#define get_prev_arena_online_prof(i) \
  (&(get_prev_arena_prof(i)->profile_online))

#define get_arena_profile_all_event_prof(i, n) \
  (&(get_arena_all_prof(i)->events[n]))

