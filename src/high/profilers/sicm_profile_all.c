#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sys/types.h>
#include <linux/perf_event.h>
#include <perfmon/pfmlib_perf_event.h>

#define SICM_RUNTIME 1
#include "sicm_runtime.h"
#include "sicm_profilers.h"
#include "sicm_profile.h"
#include "sicm_parsing.h"

void profile_all_arena_init(profile_all_info *);
void profile_all_deinit();
void profile_all_init();
void *profile_all(void *);
void profile_all_interval(int);
void profile_all_skip_interval(int);
void profile_all_post_interval(arena_profile *);
void update_page_rec(addr_t, size_t, int, int*);
void update_cache_block_rec(addr_t, size_t, int, int*);

/* Uses libpfm to figure out the event we're going to use */
void sh_get_profile_all_event() {
  int err;
  size_t i, n;
  pfm_perf_encode_arg_t pfm;

  pfm_initialize();

  /* Make sure all of the events work. Initialize the pes. */
  for(n = 0; n < profopts.num_profile_all_cpus; n++) {
    for(i = 0; i < prof.profile->num_profile_all_events; i++) {
      memset(prof.profile_all.pes[n][i], 0, sizeof(struct perf_event_attr));
      prof.profile_all.pes[n][i]->size = sizeof(struct perf_event_attr);
      memset(&pfm, 0, sizeof(pfm_perf_encode_arg_t));
      pfm.size = sizeof(pfm_perf_encode_arg_t);
      pfm.attr = prof.profile_all.pes[n][i];

      err = pfm_get_os_event_encoding(prof.profile->profile_all_events[i], PFM_PLM2 | PFM_PLM3, PFM_OS_PERF_EVENT, &pfm);
      if(err != PFM_SUCCESS) {
        fprintf(stderr, "Failed to initialize event '%s'. Aborting.\n", prof.profile->profile_all_events[i]);
        exit(1);
      }

      /* If we're profiling all, set some additional options. */
      if(should_profile_all()) {
        prof.profile_all.pes[n][i]->sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_ADDR;
        prof.profile_all.pes[n][i]->sample_period = profopts.sample_freq;
        prof.profile_all.pes[n][i]->mmap = 1;
        prof.profile_all.pes[n][i]->disabled = 1;
        prof.profile_all.pes[n][i]->exclude_kernel = 1;
        prof.profile_all.pes[n][i]->exclude_hv = 1;
        prof.profile_all.pes[n][i]->precise_ip = 2;
        prof.profile_all.pes[n][i]->task = 1;
        prof.profile_all.pes[n][i]->sample_period = profopts.sample_freq;
      }
    }
  }
}

void profile_all_arena_init(profile_all_info *info) {
  size_t i;

  info->events = orig_calloc(prof.profile->num_profile_all_events, sizeof(per_event_profile_all_info));
  for(i = 0; i < prof.profile->num_profile_all_events; i++) {
    info->events[i].total = 0;
    info->events[i].peak = 0;
  }
}

void profile_all_deinit() {
  size_t i, n;

  for(n = 0; n < profopts.num_profile_all_cpus; n++) {
    for(i = 0; i < prof.profile->num_profile_all_events; i++) {
      ioctl(prof.profile_all.fds[n][i], PERF_EVENT_IOC_DISABLE, 0);
    }
  }

  for(n = 0; n < profopts.num_profile_all_cpus; n++) {
    for(i = 0; i < prof.profile->num_profile_all_events; i++) {
      close(prof.profile_all.fds[n][i]);
    }
  }
  close(prof.profile_all.pagemap_fd);
}

void profile_all_init() {
  size_t i, n;
  pid_t pid;
  int cpu, group_fd;
  unsigned long flags;

  prof.profile_all.tid = (unsigned long) syscall(SYS_gettid);
  prof.profile_all.pagesize = (size_t) sysconf(_SC_PAGESIZE);
  prof.profile_all.pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
  if (prof.profile_all.pagemap_fd < 0) {
    fprintf(stderr, "Failed to open /proc/self/pagemap. Aborting.\n");
    exit(1);
  }

  /* This array is for storing the per-cpu, per-event data_head values. Instead of calling `poll`, we
     can see if the current data_head value is different from the previous one, and when it is,
     we know we have some new values to read. */
  prof.profile_all.prev_head = malloc(sizeof(uint64_t *) * profopts.num_profile_all_cpus);
  for(n = 0; n < profopts.num_profile_all_cpus; n++) {
    prof.profile_all.prev_head[n] = malloc(sizeof(uint64_t) * prof.profile->num_profile_all_events);
    for(i = 0; i < prof.profile->num_profile_all_events; i++) {
      prof.profile_all.prev_head[n][i] = 0;
    }
  }

  /* Allocate perf structs */
  prof.profile_all.pes = orig_malloc(sizeof(struct perf_event_attr **) * profopts.num_profile_all_cpus);
  prof.profile_all.fds = orig_malloc(sizeof(int *) * profopts.num_profile_all_cpus);
  for(n = 0; n < profopts.num_profile_all_cpus; n++) {
    prof.profile_all.pes[n] = orig_malloc(sizeof(struct perf_event_attr *) * prof.profile->num_profile_all_events);
    prof.profile_all.fds[n] = orig_malloc(sizeof(int) * prof.profile->num_profile_all_events);
    for(i = 0; i < prof.profile->num_profile_all_events; i++) {
      prof.profile_all.pes[n][i] = orig_malloc(sizeof(struct perf_event_attr));
      prof.profile_all.fds[n][i] = 0;
    }
  }

  /* Use libpfm to fill the pe struct */
  sh_get_profile_all_event();

  /* Open all perf file descriptors */
  for(n = 0; n < profopts.num_profile_all_cpus; n++) {
    /* A value of -1 for both `pid` and `cpu` is not valid. */
    if(profopts.profile_all_cpus[n] == -1) {
      pid = 0;
    } else {
      pid = -1;
    }
    cpu = profopts.profile_all_cpus[n];
    group_fd = -1;
    flags = 0;
    for(i = 0; i < prof.profile->num_profile_all_events; i++) {
      prof.profile_all.fds[n][i] = syscall(__NR_perf_event_open, prof.profile_all.pes[n][i], pid, cpu, group_fd, flags);
      if(prof.profile_all.fds[n][i] == -1) {
        fprintf(stderr, "Error opening perf event %d (0x%llx) on cpu %d: %s\n", i, prof.profile_all.pes[n][i]->config, cpu, strerror(errno));
        exit(1);
      }
    }
  }

  /* mmap the perf file descriptors */
  prof.profile_all.metadata = orig_malloc(sizeof(struct perf_event_mmap_page **) * profopts.num_profile_all_cpus);
  for(n = 0; n < profopts.num_profile_all_cpus; n++) {
    prof.profile_all.metadata[n] = orig_malloc(sizeof(struct perf_event_mmap_page *) * prof.profile->num_profile_all_events);
    for(i = 0; i < prof.profile->num_profile_all_events; i++) {
      prof.profile_all.metadata[n][i] = mmap(NULL,
                                          prof.profile_all.pagesize + (prof.profile_all.pagesize * profopts.max_sample_pages),
                                          PROT_READ | PROT_WRITE,
                                          MAP_SHARED,
                                          prof.profile_all.fds[n][i],
                                          0);
      if(prof.profile_all.metadata[n][i] == MAP_FAILED) {
        fprintf(stderr, "Failed to mmap room (%zu bytes) for perf samples. Aborting with:\n%s\n",
                prof.profile_all.pagesize + (prof.profile_all.pagesize * profopts.max_sample_pages), strerror(errno));
        exit(1);
      }
    }
  }

  /* Start the events sampling */
  for(n = 0; n < profopts.num_profile_all_cpus; n++) {
    for(i = 0; i < prof.profile->num_profile_all_events; i++) {
      ioctl(prof.profile_all.fds[n][i], PERF_EVENT_IOC_RESET, 0);
      ioctl(prof.profile_all.fds[n][i], PERF_EVENT_IOC_ENABLE, 0);
    }
  }
}

void *profile_all(void *a) {
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

  /* Wait for signals */
  while(1) { }
}

/* Just copies the previous value */
void profile_all_skip_interval(int s) {
}

/* Adds up accesses to the arenas */
void profile_all_interval(int s) {
  uint64_t head, tail, buf_size;
  arena_info *arena;
  void *addr;
  char *base, *begin, *end, break_next_site;
  struct sample *sample;
  struct perf_event_header *header;
  int err, site_id;
  size_t i, n, x;
  arena_profile *aprof;
  per_event_profile_all_info *per_event_aprof;
  struct pollfd pfd;
  object_info_ptr oip;
  uint64_t_ptr site_profile;
  tree_it(addr_t, object_info_ptr) oit;
  tree_it(int, uint64_t_ptr) sit;
  addr_t obj_base;
  size_t obj_size;

  /* Loop over all arenas and clear their accumulators */
  for(i = 0; i < prof.profile->num_profile_all_events; i++) {
    arena_arr_for(n) {
      prof_check_good(arena, aprof, n);
      aprof->profile_all.events[i].current = 0;
    }
  }

  /* Loops over all CPUs */
  for(x = 0; x < profopts.num_profile_all_cpus; x++) {
    /* Loops over all PROFILE_ALL events */
    for(i = 0; i < prof.profile->num_profile_all_events; i++) {

#if 0
      /* Wait for the perf buffer to be ready */
      pfd.fd = prof.profile_all.fds[x][i];
      pfd.events = POLLIN;
      pfd.revents = 0;
      err = poll(&pfd, 1, 1);
      if(err == 0) {
        /* Finished with this interval, there are no ready perf buffers to
         * read from */
        return;
      } else if(err == -1) {
        fprintf(stderr, "Error occurred polling. Aborting.\n");
        exit(1);
      }
#endif

      /* Grab the head. If the head is the same as the previous one, we can just
         move on to the next event; the buffer isn't ready to read yet. */
      head = prof.profile_all.metadata[x][i]->data_head;
#if 0
      if (i==0) {
        if(head == prof.profile_all.prev_head[x][i]) {
          fprintf(profopts.profile_output_file, "x: %4d head: %12zu prev: %12zu start: %p off: %p end: %p size: %llu\n",
                  x, head, prof.profile_all.prev_head[x][i],
                  ( ((intptr_t)prof.profile_all.metadata[x][i]) +
                    ((intptr_t)prof.profile_all.pagesize) ),
                  ( ((intptr_t)prof.profile_all.metadata[x][i]) +
                      prof.profile_all.metadata[x][i]->data_offset),
                  ( ((intptr_t)prof.profile_all.metadata[x][i]) +
                    ( ((intptr_t)prof.profile_all.pagesize) +
                      ((intptr_t)(prof.profile_all.pagesize * profopts.max_sample_pages))
                    )
                  ), prof.profile_all.metadata[x][i]->data_size
                 );
        } else {
          fprintf(profopts.profile_output_file, "y: %4d head: %12zu prev: %12zu start: %p off: %p end: %p %llu\n",
                  x, head, prof.profile_all.prev_head[x][i],
                  ( ((intptr_t)prof.profile_all.metadata[x][i]) +
                    ((intptr_t)prof.profile_all.pagesize) ),
                  ( ((intptr_t)prof.profile_all.metadata[x][i]) +
                      prof.profile_all.metadata[x][i]->data_offset),
                  ( ((intptr_t)prof.profile_all.metadata[x][i]) +
                    ( ((intptr_t)prof.profile_all.pagesize) +
                      ((intptr_t)(prof.profile_all.pagesize * profopts.max_sample_pages))
                    )
                  ), prof.profile_all.metadata[x][i]->data_size
                 );
        }
      }
      fflush(profopts.profile_output_file);
#endif
#if 0
      if(head == prof.profile_all.prev_head[x][i]) {
        pid_t pid;
        int cpu, group_fd;
        unsigned long flags;
        
        ioctl(prof.profile_all.fds[x][i], PERF_EVENT_IOC_DISABLE, 0);
        close(prof.profile_all.fds[x][i]);
        munmap( prof.profile_all.metadata[x][i], 
          prof.profile_all.pagesize +
          (prof.profile_all.pagesize * profopts.max_sample_pages)
        );

        if(profopts.profile_all_cpus[x] == -1) {
          pid = 0;
        } else {
          pid = -1;
        }
        cpu = profopts.profile_all_cpus[x];
        group_fd = -1;
        flags = 0;

        prof.profile_all.fds[x][i] = syscall(__NR_perf_event_open,
          prof.profile_all.pes[x][i], pid, cpu, group_fd, flags);
        if(prof.profile_all.fds[x][i] == -1) {
          fprintf(stderr, "Error opening perf event %d (0x%llx) on cpu %d: %s\n",
            i, prof.profile_all.pes[x][i]->config, cpu, strerror(errno));
          exit(1);
        }

        prof.profile_all.metadata[x][i] = mmap(NULL,
          prof.profile_all.pagesize + (prof.profile_all.pagesize *
          profopts.max_sample_pages), PROT_READ | PROT_WRITE, MAP_SHARED,
          prof.profile_all.fds[x][i], 0);
        if(prof.profile_all.metadata[x][i] == MAP_FAILED) {
          fprintf(stderr, "Failed to mmap room (%zu bytes) for perf samples. Aborting with:\n%s\n",
                  prof.profile_all.pagesize + (prof.profile_all.pagesize * profopts.max_sample_pages), strerror(errno));
          exit(1);
        }

        prof.profile_all.prev_head[x][i] = 0;
        ioctl(prof.profile_all.fds[x][i], PERF_EVENT_IOC_RESET, 0);
        ioctl(prof.profile_all.fds[x][i], PERF_EVENT_IOC_ENABLE, 0);
        continue;
      }
#endif
      if(head == prof.profile_all.prev_head[x][i]) {
        continue;
      }
      prof.profile_all.prev_head[x][i] = head;

      tail = prof.profile_all.metadata[x][i]->data_tail;
      buf_size = prof.profile_all.pagesize * profopts.max_sample_pages;
      asm volatile("" ::: "memory"); /* Block after reading data_head, per perf docs */

      base = (char *)prof.profile_all.metadata[x][i] + prof.profile_all.pagesize;
      begin = base + tail % buf_size;
      end = base + head % buf_size;


      /* Read all of the samples */
      if (profopts.should_profile_objects) {

        pthread_rwlock_rdlock(&tracker.profile_objects_map_lock);
        while(begin <= (end - 8)) {

          header = (struct perf_event_header *)begin;
          if(header->size == 0) {
            break;
          }
          sample = (struct sample *) (begin + 8);
          addr = (void *) (sample->addr);

          if(addr) {
            oit = tree_gtr(tracker.profile_objects_map, addr);
            tree_it_prev(oit);

            if (tree_it_good(oit)) {
              obj_base = tree_it_key(oit);
              obj_size = ((tree_it_val(oit))->size);
              site_id = ((tree_it_val(oit))->site_id);

              if (addr < (obj_base + obj_size)) {
                sit = tree_lookup(tracker.profile_sites_map, site_id);
                if (tree_it_good(sit)) {
                  site_profile = tree_it_val(sit);
                  site_profile[i] += 1; 
                }

                if (profopts.track_pages) {
                  update_page_rec(addr, i, 1, &site_id);
                }

                if (profopts.track_cache_blocks) {
                  update_cache_block_rec(addr, i, 1, &site_id);
                }
              }
            }
          }

          /* Increment begin by the size of the sample */
          if(((char *)header + header->size) == base + buf_size) {
            begin = base;
          } else {
            begin = begin + header->size;
          }
        }
        pthread_rwlock_unlock(&tracker.profile_objects_map_lock);

      } else {

        pthread_rwlock_rdlock(&tracker.extents_lock);
        while(begin <= (end - 8)) {

          header = (struct perf_event_header *)begin;
          if(header->size == 0) {
            break;
          }
          sample = (struct sample *) (begin + 8);
          addr = (void *) (sample->addr);

          if(addr) {
            /* Search for which extent it goes into */
            extent_arr_for(tracker.extents, n) {
              if(!tracker.extents->arr[n].start && !tracker.extents->arr[n].end) continue;
              arena = (arena_info *)tracker.extents->arr[n].arena;
              if((addr >= tracker.extents->arr[n].start) && (addr <= tracker.extents->arr[n].end) && arena) {

                /* Record this access */
                get_arena_profile_all_event_prof(arena->index, i)->current++;
                get_arena_profile_all_event_prof(arena->index, i)->total++;

                if (profopts.track_pages) {
                  update_page_rec(addr, i, arena->num_alloc_sites, arena->alloc_sites);
                }

                if (profopts.track_cache_blocks) {
                  update_cache_block_rec(addr, i, arena->num_alloc_sites, arena->alloc_sites);
                }
              }
            }
          }

          /* Increment begin by the size of the sample */
          if(((char *)header + header->size) == base + buf_size) {
            begin = base;
          } else {
            begin = begin + header->size;
          }
        }
        pthread_rwlock_unlock(&tracker.extents_lock);
      }
    
      /* Let perf know that we've read this far */
      prof.profile_all.metadata[x][i]->data_tail = head;
      __sync_synchronize();
    }
  }
  
  for(i = 0; i < prof.profile->num_profile_all_events; i++) {
    arena_arr_for(n) {
      prof_check_good(arena, aprof, n);
      if(profopts.profile_all_multipliers) {
        aprof->profile_all.events[i].current *= profopts.profile_all_multipliers[i];
      }
      aprof->profile_all.events[i].total += aprof->profile_all.events[i].current;
    }
  }
}

void profile_all_post_interval(arena_profile *aprof) {
  per_event_profile_all_info *per_event_aprof;
  profile_all_info *aprof_all;
  size_t i;

  /* All we need to do here is maintain the peak */
  aprof_all = &(aprof->profile_all);
  for(i = 0; i < prof.profile->num_profile_all_events; i++) {
    per_event_aprof = &(aprof_all->events[i]);
    if(aprof_all->events[i].current > per_event_aprof->peak) {
      per_event_aprof->peak = aprof_all->events[i].current;
    }
  }
}

void profile_all_post_interval_region(region_profile_ptr rp) {
  per_event_profile_all_info *per_event_rprof;
  profile_all_info *rprof_all;
  size_t i;

  /* All we need to do here is maintain the peak */
  rprof_all = &(rp->rprof);
  for(i = 0; i < prof.profile->num_profile_all_events; i++) {
    per_event_rprof = &(rprof_all->events[i]);
    if(rprof_all->events[i].current > per_event_rprof->peak) {
      per_event_rprof->peak = rprof_all->events[i].current;
    }
  }
}

void profile_all_post_interval_region_map( tree(addr_t, region_profile_ptr) map ) {
  tree_it(addr_t, region_profile_ptr) it;

  tree_traverse(map, it) {
    profile_all_post_interval_region(tree_it_val(it));
  }
}

void update_page_rec(addr_t addr, size_t evt, int arena_num_alloc_sites, int *arena_alloc_sites) {
  unsigned i, j, diff_num;
  int *diff_sites;
  region_profile_ptr page_rec, new_rec;
  tree_it(addr_t, region_profile_ptr) it;
  addr_t page_addr = (addr_t)(PAGE_ADDR(addr));
 
  it = tree_lookup(prof.profile->page_map, page_addr);
  if (!(tree_it_good(it))) {
    page_rec = get_new_region_profile();
    tree_insert(prof.profile->page_map, page_addr, page_rec);
  } else {
    page_rec = tree_it_val(it);
  }

  if (page_rec->pfn == PFN_INVALID) {
    get_pfn(prof.profile_all.pagemap_fd, addr, page_rec);
  }

  if (page_rec->alloc_sites == NULL) {

    page_rec->alloc_sites = (int*) orig_malloc(sizeof(int) * arena_num_alloc_sites);
    if (page_rec->alloc_sites == NULL) {
      fprintf(stderr, "update_page_rec: out of memory\n");
      exit(-ENOMEM);
    }
    for (i = 0; i < arena_num_alloc_sites; i++) {
      page_rec->alloc_sites[i] = arena_alloc_sites[i];
    }
    page_rec->num_alloc_sites = arena_num_alloc_sites;

  } else {
    /* store sites that are not already on the record into diff_sites */
    diff_sites = (int*) orig_malloc(arena_num_alloc_sites*sizeof(int));
    if (diff_sites == NULL) {
      fprintf(stderr, "update_page_rec: out of memory\n");
      exit(-ENOMEM);
    }

    diff_num = 0;
    for (i = 0; i < arena_num_alloc_sites; i++) {
      for (j = 0; j < page_rec->num_alloc_sites; j++) {
        if (arena_alloc_sites[i] == page_rec->alloc_sites[j]) {
          break;
        }
      }
      if (j == page_rec->num_alloc_sites) {
        diff_sites[diff_num] = arena_alloc_sites[i];
        diff_num++;
      }
    }

    page_rec->alloc_sites = orig_realloc( page_rec->alloc_sites,
      (((page_rec->num_alloc_sites) + diff_num) * sizeof(int)) );
    if (page_rec->alloc_sites == NULL) {
      fprintf(stderr, "update_page_rec: out of memory\n");
      exit(-ENOMEM);
    }

    for (i = page_rec->num_alloc_sites, j = 0; j < diff_num; i++, j++) {
      page_rec->alloc_sites[i] = diff_sites[j];
    }

    orig_free(diff_sites);
  }

  page_rec->rprof.events[evt].current++;
  page_rec->rprof.events[evt].total++;
}

void update_cache_block_rec(addr_t addr, size_t evt, int arena_num_alloc_sites, int *arena_alloc_sites) {
  unsigned i, j, diff_num;
  int *diff_sites;
  region_profile_ptr cache_block_rec;
  tree_it(addr_t, region_profile_ptr) it;
  addr_t cache_block_addr = (addr_t)(CACHE_BLOCK_ADDR(addr));

  it = tree_lookup(prof.profile->cache_block_map, cache_block_addr);
  if (!(tree_it_good(it))) {
    cache_block_rec = get_new_region_profile();
    tree_insert(prof.profile->cache_block_map, cache_block_addr, cache_block_rec);
  } else {
    cache_block_rec = tree_it_val(it);
  }

  if (cache_block_rec->alloc_sites == NULL) {

    cache_block_rec->alloc_sites = (int*) orig_malloc(sizeof(int) * arena_num_alloc_sites);
    if (cache_block_rec->alloc_sites == NULL) {
      fprintf(stderr, "update_cache_block_rec: out of memory\n");
      exit(-ENOMEM);
    }
    for (i = 0; i < arena_num_alloc_sites; i++) {
      cache_block_rec->alloc_sites[i] = arena_alloc_sites[i];
    }
    cache_block_rec->num_alloc_sites = arena_num_alloc_sites;

  } else {
    /* store sites that are not already on the record into diff_sites */
    diff_sites = (int*) orig_malloc(arena_num_alloc_sites*sizeof(int));
    if (diff_sites == NULL) {
      fprintf(stderr, "update_cache_block_rec: out of memory\n");
      exit(-ENOMEM);
    }

    diff_num = 0;
    for (i = 0; i < arena_num_alloc_sites; i++) {
      for (j = 0; j < cache_block_rec->num_alloc_sites; j++) {
        if (arena_alloc_sites[i] == cache_block_rec->alloc_sites[j]) {
          break;
        }
      }
      if (j == cache_block_rec->num_alloc_sites) {
        diff_sites[diff_num] = arena_alloc_sites[i];
        diff_num++;
      }
    }

    cache_block_rec->alloc_sites = orig_realloc( cache_block_rec->alloc_sites,
      (((cache_block_rec->num_alloc_sites) + diff_num) * sizeof(int)) );
    if (cache_block_rec->alloc_sites == NULL) {
      fprintf(stderr, "update_cache_block_rec: out of memory\n");
      exit(-ENOMEM);
    }

    for (i = cache_block_rec->num_alloc_sites, j = 0; j < diff_num; i++, j++) {
      cache_block_rec->alloc_sites[i] = diff_sites[j];
    }

    orig_free(diff_sites);
  }

  cache_block_rec->rprof.events[evt].current++;
  cache_block_rec->rprof.events[evt].total++;
}

