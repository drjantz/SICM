#pragma once

#include <inttypes.h>
#include <stdatomic.h>
#include "sicm_malloc_free.h"
#include "sicm_low.h"
#include "sicm_tree.h"

#define CGROUP_ROOT "/sys/fs/cgroup/unified/0"
#define CGROUP_TASKS (CGROUP_ROOT "/cgroup.procs")
#define CGROUP_MEM_HIGH (CGROUP_ROOT "/memory.high")
#define CGROUP_MEM_MAX (CGROUP_ROOT "/memory.max")
#define CGROUP_MEM_CURRENT (CGROUP_ROOT "/memory.current")
#define CGROUP_MEM_COMPRESS (CGROUP_ROOT "/memory.compress")
#define PROC_SELF_STATM "/proc/self/statm"
#define ZSWAP_STORED_PAGES "/sys/kernel/debug/zswap/stored_pages"
#define ZSWAP_POOL_TOTAL_SIZE "/sys/kernel/debug/zswap/pool_total_size"

#ifdef SICM_RUNTIME
#include "sicm_impl.h"
#else
typedef struct extent_arr extent_arr;
typedef struct sarena sarena;
#endif

extern char sh_initialized;
extern void *(*orig_malloc_ptr)(size_t);
extern void *(*orig_calloc_ptr)(size_t, size_t);
extern void *(*orig_realloc_ptr)(void *, size_t);
extern void (*orig_free_ptr)(void *);

enum arena_layout {
  EXCLUSIVE_ARENAS, /* One arena per thread */
  EXCLUSIVE_DEVICE_ARENAS, /* One arena per device per thread */
  SHARED_SITE_ARENAS, /* One arena per allocation site */
  BIG_SMALL_ARENAS, /* Per-thread arenas for small allocations, shared site ones for larger sites */
  EXCLUSIVE_COMPRESS_ARENAS, /* One arena per device per thread */
  INVALID_LAYOUT
};
#define DEFAULT_ARENA_LAYOUT INVALID_LAYOUT

/* Information about a single allocation */
typedef void *addr_t;
typedef struct alloc_info {
  int index;
  size_t size;
} alloc_info;
typedef alloc_info *alloc_info_ptr;
use_tree(addr_t, alloc_info_ptr);

/* Information about a single object allocation */
typedef struct object_info {
  int site_id;
  size_t size;
} object_info;
typedef object_info *object_info_ptr;
use_tree(addr_t, object_info_ptr);

typedef uint64_t * uint64_t_ptr;
use_tree(int, uint64_t_ptr);

/* Information about a single arena */
typedef struct arena_info {
  int *alloc_sites, num_alloc_sites;
  unsigned index; /* Index into the arenas array */
  sicm_arena arena; /* SICM's low-level interface pointer */
  size_t size; /* The total size of the arena's allocations */
} arena_info;

/* Information about a single site */
typedef sicm_device * deviceptr;
typedef struct site_info {
  pthread_rwlock_t lock;
  deviceptr device;
  int arena;
  size_t size;
  char big;
} site_info;
typedef site_info * siteinfo_ptr;

/* Declare the trees */
use_tree(deviceptr, int);
use_tree(int, siteinfo_ptr);

/* Keeps track of all allocated data: arenas, extents, threads, etc. */
typedef struct tracker_struct {
  /* File to output log to */
  FILE *log_file;
  
  /* Stores all machine devices and device
   * we should bind to by default */
  struct sicm_device_list device_list;
  int num_numa_nodes;
  deviceptr lower_device, upper_device, default_device;

  /* Stores arena indices associated with a device,
   * for the per-device arena layouts only. */
  pthread_rwlock_t device_arenas_lock;
  tree(deviceptr, int) device_arenas;

  /* Keep track of all extents */
  pthread_rwlock_t extents_lock;
  extent_arr *extents;

  /* Associates a site ID with the arena that it's in */
  atomic_int *site_arenas;
  atomic_intptr_t *site_devices;
  atomic_char *site_bigs;
  atomic_size_t *site_sizes;
  atomic_int *site_compress;

  /* Arena layout */
  enum arena_layout layout;
  size_t big_small_threshold;

  /* Keeps track of arenas */
  arena_info **arenas;
  int max_arenas, arenas_per_thread, max_sites_per_arena, max_sites;
  int max_index;
  pthread_mutex_t arena_lock;

  /* MRJ -- I really don't know why this is necessary */
  pthread_mutex_t pagemap_lock;

  /* Only for profile_allocs. Stores allocated pointers as keys,
   * their arenas as values. For looking up which arena a `free` call
   * should go to.
   */
  tree(addr_t, alloc_info_ptr) profile_allocs_map;
  pthread_rwlock_t profile_allocs_map_lock;

  /* Only for profile_objects.
   */
  tree(addr_t, object_info_ptr) profile_objects_map;
  pthread_rwlock_t profile_objects_map_lock;
  tree(int, uint64_t_ptr) profile_sites_map;

  int max_threads;
  atomic_int current_thread_index;
  atomic_int arena_counter;
  int num_static_sites;
  
  /* Ensures that nothing happens before initialization */
  char finished_initializing;
} tracker_struct;

/* Options for if/when/how to profile. Initialized in src/high/sicm_runtime_init.c,
 * used by src/high/sicm_profile.c.
 */
typedef struct profiling_options {
  int should_profile_dirty;
  int should_profile_objects;
  int track_pages, track_cache_blocks;
  int page_profile_intervals, cache_block_profile_intervals;
  char free_buffer;
  
  /* bitmask of which profiling types are enabled */
  char profile_type_flags;
  
  int should_run_rdspy;
  int profile_latency_set_multipliers;
  int print_profile_intervals;
  int profile_bw_relative;
  size_t num_profile_all_multipliers;
  float *profile_all_multipliers;

  /* Sample rates */
  size_t profile_rate_nseconds;
  unsigned long profile_rss_skip_intervals,
                profile_dirty_skip_intervals,
                profile_all_skip_intervals,
                profile_bw_skip_intervals,
                profile_latency_skip_intervals,
                profile_extent_size_skip_intervals,
                profile_allocs_skip_intervals,
                profile_online_skip_intervals;
  int sample_freq;
  int max_sample_pages;

  /* Input and output for profiling information */
  FILE *profile_input_file;
  FILE *profile_output_file;
  FILE *profile_online_debug_file; /* For the verbose online approach */

  FILE *page_profile_output_file;
  FILE *cache_profile_output_file;
  FILE *dirty_profile_output_file;
  FILE *site_profile_output_file;
  FILE *compress_stats_file;

  /* Online */
  float profile_online_reconf_weight_ratio;
  char profile_online_nobind;
  float profile_online_last_iter_value;
  float profile_online_last_iter_weight;
  unsigned long profile_online_grace_accesses;
  size_t profile_online_hot_intervals;
  int profile_online_use_last_interval;
  char profile_online_orig; /* Online strat */
  char profile_online_ski; /* Online strat */
  char *profile_online_value;
  char *profile_online_weight;
  char *profile_online_sort;
  char *profile_online_packing_algo;
  unsigned long profile_online_reserved_bytes;

  /* Array of cpu numbers for profile_all */
  size_t num_profile_all_cpus;
  int *profile_all_cpus;

  /* Array of strings for profile_all events */
  size_t num_profile_all_events;
  char **profile_all_events;

  /* Array of sockets to profile on, and one CPU per socket to use to profile */
  size_t num_profile_skt_cpus;
  int *profile_skt_cpus;
  int *profile_skts;
  
  /* Array of strings for profile_bw events */
  size_t num_profile_bw_events;
  char **profile_bw_events;
  
  /* Array of strings for profile_latency events */
  size_t num_profile_latency_events;
  char **profile_latency_events;
  char *profile_latency_clocktick_event;

  /* Array of strings of IMCs for per-IMC profiling */
  char **imcs;
  int num_imcs;
} profiling_options;

/* Symbols that both sicm_runtime.c and sicm_profile.c need */
extern tracker_struct tracker;
extern profiling_options profopts;

/* Function declarations */
void sh_start_profile_master_thread();
void sh_stop_profile_master_thread();
void sh_create_extent(sarena *arena, void *begin, void *end);
void sh_delete_extent(sarena *arena, void *begin, void *end);
int get_arena_index(int id, size_t sz);
__attribute__((constructor)) void sh_init();
__attribute__((destructor)) void sh_terminate();
#ifdef __cplusplus
/* For Bjarnebois */
extern "C" {
#endif
  void* sh_alloc_exact(int id, size_t sz);
  void* sh_alloc(int id, size_t sz);
  void* sh_aligned_alloc(int id, size_t alignment, size_t sz);
  void* sh_memalign(int id, size_t alignment, size_t sz);
  int sh_posix_memalign(int id, void **ptr, size_t alignment, size_t sz);
  void* sh_calloc(int id, size_t num, size_t sz);
  void* sh_realloc(int id, void *ptr, size_t sz);
  void sh_free(void* ptr);
#ifdef __cplusplus
}
#endif

/* Some helper macros */
#define arena_arr_for(i) \
  for(i = 0; i <= tracker.max_index; i++)
#define arena_check_good(a, i) \
  a = tracker.arenas[i]; \
  if(!a) continue;
  
/* Used to determine which types of profiling are enabled */
#define should_profile() \
  profopts.profile_type_flags
#define should_profile_all() \
  profopts.profile_type_flags & (1 << 0)
#define should_profile_rss() \
  profopts.profile_type_flags & (1 << 1)
#define should_profile_extent_size() \
  profopts.profile_type_flags & (1 << 2)
#define should_profile_allocs() \
  profopts.profile_type_flags & (1 << 3)
#define should_profile_bw() \
  profopts.profile_type_flags & (1 << 4)
#define should_profile_latency() \
  profopts.profile_type_flags & (1 << 5)
#define should_profile_online() \
  profopts.profile_type_flags & (1 << 6)
#define should_profile_compress_stats() \
  profopts.profile_type_flags & (1 << 7)
  
/* Used to set which types of profiling are enabled */
#define enable_profile_all() \
  profopts.profile_type_flags = profopts.profile_type_flags | 1
#define enable_profile_rss() \
  profopts.profile_type_flags = profopts.profile_type_flags | (1 << 1)
#define enable_profile_extent_size() \
  profopts.profile_type_flags = profopts.profile_type_flags | (1 << 2)
#define enable_profile_allocs() \
  profopts.profile_type_flags = profopts.profile_type_flags | (1 << 3)
#define enable_profile_bw() \
  profopts.profile_type_flags = profopts.profile_type_flags | (1 << 4)
#define enable_profile_latency() \
  profopts.profile_type_flags = profopts.profile_type_flags | (1 << 5)
#define enable_profile_online() \
  profopts.profile_type_flags = profopts.profile_type_flags | (1 << 6)
#define enable_profile_compress_stats() \
  profopts.profile_type_flags = profopts.profile_type_flags | (1 << 7)
