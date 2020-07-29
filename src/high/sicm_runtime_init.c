/* Required for dlsym */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdbool.h>
#include <numa.h>

#define SICM_RUNTIME 1
#include "sicm_runtime.h"
#include "sicm_rdspy.h"

/* Options for profiling */
profiling_options profopts = {0};

/* Keeps track of arenas, extents, etc. */
tracker_struct tracker = {0};

/* Takes a string as input and outputs which arena layout it is */
enum arena_layout parse_layout(char *env) {
  size_t max_chars;

  max_chars = 32;

  if(strncmp(env, "EXCLUSIVE_ARENAS", max_chars) == 0) {
    return EXCLUSIVE_ARENAS;
  } else if(strncmp(env, "EXCLUSIVE_DEVICE_ARENAS", max_chars) == 0) {
    return EXCLUSIVE_DEVICE_ARENAS;
  } else if(strncmp(env, "SHARED_SITE_ARENAS", max_chars) == 0) {
    return SHARED_SITE_ARENAS;
  } else if(strncmp(env, "BIG_SMALL_ARENAS", max_chars) == 0) {
    return BIG_SMALL_ARENAS;
  }

  return INVALID_LAYOUT;
}

/* Converts an arena_layout to a string */
char *layout_str(enum arena_layout layout) {
  switch(layout) {
    case EXCLUSIVE_ARENAS:
      return "EXCLUSIVE_ARENAS";
    case EXCLUSIVE_DEVICE_ARENAS:
      return "EXCLUSIVE_DEVICE_ARENAS";
    case SHARED_SITE_ARENAS:
      return "SHARED_SITE_ARENAS";
    case BIG_SMALL_ARENAS:
      return "BIG_SMALL_ARENAS";
    default:
      break;
  }

  return "INVALID_LAYOUT";
}

/* Gets the SICM low-level device that corresponds to a NUMA node ID */
sicm_device *get_device_from_numa_node(int id) {
  deviceptr retval;
  deviceptr device;
  int i;

  retval = NULL;
  /* Figure out which device the NUMA node corresponds to */
  device = *(tracker.device_list.devices);
  for(i = 0; i < tracker.device_list.count; i++) {
    /* If the device has a NUMA node, and if that node is the node we're
     * looking for.
     */
    if(sicm_numa_id(device) == id) {
      retval = device;
      break;
    }
    device++;
  }

  if(retval == NULL) {
    fprintf(stderr, "Couldn't find an appropriate device for NUMA node %d, out of %lu devices.\n", id, tracker.device_list.count);
    exit(1);
  }

  return retval;
}

/* Gets environment variables and sets up globals */
void set_options() {
  char *env, *str, *line, guidance, found_guidance;
  long long tmp_val;
  deviceptr device;
  size_t i, n;
  int node, cpu, site, num_cpus, num_nodes;
  FILE *guidance_file;
  ssize_t len;
  struct bitmask *cpus, *nodes;
  char flag;
  
  profopts.profile_type_flags = 0;
  
  env = getenv("SH_FREE_BUFFER");
  profopts.free_buffer = 0;
  if(env) {
    profopts.free_buffer = 1;
  }

  /* See if there's profiling information that we can use later */
  env = getenv("SH_PROFILE_INPUT_FILE");
  profopts.profile_input_file = NULL;
  if(env) {
    profopts.profile_input_file = fopen(env, "r");
    if(!profopts.profile_input_file) {
      fprintf(stderr, "Failed to open profile input file. Aborting.\n");
      exit(1);
    }
  }

  env = getenv("SH_PROFILE_OUTPUT_FILE");
  profopts.profile_output_file = NULL;
  if(env) {
    profopts.profile_output_file = fopen(env, "w");
    if(!profopts.profile_output_file) {
      fprintf(stderr, "Failed to open profile output file. Aborting.\n");
      exit(1);
    }
  }

  env = getenv("SH_PAGE_PROFILE_OUTPUT_FILE");
  profopts.page_profile_output_file = NULL;
  if(env) {
    profopts.page_profile_output_file = fopen(env, "w");
    if(!profopts.page_profile_output_file) {
      fprintf(stderr, "Failed to open page profile output file. Aborting.\n");
      exit(1);
    }
  }

  env = getenv("SH_CACHE_PROFILE_OUTPUT_FILE");
  profopts.cache_profile_output_file = NULL;
  if(env) {
    profopts.cache_profile_output_file = fopen(env, "w");
    if(!profopts.cache_profile_output_file) {
      fprintf(stderr, "Failed to open cache profile output file. Aborting.\n");
      exit(1);
    }
  }

  env = getenv("SH_SITE_PROFILE_OUTPUT_FILE");
  profopts.site_profile_output_file = NULL;
  if(env) {
    profopts.site_profile_output_file = fopen(env, "w");
    if(!profopts.site_profile_output_file) {
      fprintf(stderr, "Failed to open page profile output file. Aborting.\n");
      exit(1);
    }
  }

  env = getenv("SH_DIRTY_PROFILE_OUTPUT_FILE");
  profopts.dirty_profile_output_file = NULL;
  if(env) {
    profopts.dirty_profile_output_file = fopen(env, "w");
    if(!profopts.dirty_profile_output_file) {
      fprintf(stderr, "Failed to open dirty profile output file. Aborting.\n");
      exit(1);
    }
  }

  /* Output the chosen options to this file */
  env = getenv("SH_LOG_FILE");
  tracker.log_file = NULL;
  if(env) {
    tracker.log_file = fopen(env, "w");
    if(!tracker.log_file) {
      fprintf(stderr, "Failed to open the specified logfile: '%s'. Aborting.\n", env);
      exit(1);
    }
    printf("Outputting to '%s'.\n", env);
    fflush(stdout);
    fprintf(tracker.log_file, "===== OPTIONS =====\n");
  } else {
    printf("Not outputting to a logfile.\n");
    fflush(stdout);
  }

  /* Should we generate and attempt to use per-interval profiling information? */
  env = getenv("SH_PRINT_PROFILE_INTERVALS");
  profopts.print_profile_intervals = 0;
  if(env) {
    profopts.print_profile_intervals = 1;
  }

  /* Do we want to use the online approach, moving arenas around devices automatically? */
  env = getenv("SH_PROFILE_ONLINE");
  profopts.profile_online_skip_intervals = 0;
  if(env) {
    enable_profile_online();

    env = getenv("SH_PROFILE_ONLINE_DEBUG_FILE");
    profopts.profile_online_debug_file = NULL;
    if(env) {
      profopts.profile_online_debug_file = fopen(env, "w");
      if(!profopts.profile_online_debug_file) {
        fprintf(stderr, "Failed to open profile_online debug file. Aborting.\n");
        exit(1);
      }
    }
    
    env = getenv("SH_PROFILE_ONLINE_RESERVED_BYTES");
    profopts.profile_online_reserved_bytes = 0;
    if(env) {
      profopts.profile_online_reserved_bytes = strtoul(env, NULL, 0);
    }
    
    /* Grace period at the beginning of a run. Until this number of profiling accesses is reached,
       the profile_online won't rebind any sites. */
    env = getenv("SH_PROFILE_ONLINE_GRACE_ACCESSES");
    profopts.profile_online_grace_accesses = 0;
    if(env) {
      profopts.profile_online_grace_accesses = strtoul(env, NULL, 0);
    }

    /* Purely to measure the overhead of the online approach without doing any special binding */
    env = getenv("SH_PROFILE_ONLINE_NOBIND");
    profopts.profile_online_nobind = 0;
    if(env) {
      profopts.profile_online_nobind = 1;
    }

    env = getenv("SH_PROFILE_ONLINE_SKIP_INTERVALS");
    profopts.profile_online_skip_intervals = 1;
    if(env) {
      profopts.profile_online_skip_intervals = strtoul(env, NULL, 0);
    }
    
    env = getenv("SH_PROFILE_ONLINE_VALUE");
    if(env) {
      profopts.profile_online_value = orig_malloc((strlen(env) + 1) * sizeof(char));
      strcpy(profopts.profile_online_value, env);
    }
    
    env = getenv("SH_PROFILE_ONLINE_WEIGHT");
    if(env) {
      profopts.profile_online_weight = orig_malloc((strlen(env) + 1) * sizeof(char));
      strcpy(profopts.profile_online_weight, env);
    }

    env = getenv("SH_PROFILE_ONLINE_SORT");
    if(env) {
      profopts.profile_online_sort = orig_malloc((strlen(env) + 1) * sizeof(char));
      strcpy(profopts.profile_online_sort, env);
    }
    
    env = getenv("SH_PROFILE_ONLINE_PACKING_ALGO");
    if(env) {
      profopts.profile_online_packing_algo = orig_malloc((strlen(env) + 1) * sizeof(char));
      strcpy(profopts.profile_online_packing_algo, env);
    }
    
    env = getenv("SH_PROFILE_ONLINE_USE_LAST_INTERVAL");
    profopts.profile_online_use_last_interval = 0;
    if(env) {
      profopts.profile_online_use_last_interval = 1;
    }

    env = getenv("SH_PROFILE_ONLINE_LAST_ITER_VALUE");
    profopts.profile_online_last_iter_value = 0.0;
    if(env) {
      profopts.profile_online_last_iter_value = strtof(env, NULL);
    }

    env = getenv("SH_PROFILE_ONLINE_LAST_ITER_WEIGHT");
    profopts.profile_online_last_iter_weight = 0.0;
    if(env) {
      profopts.profile_online_last_iter_weight = strtof(env, NULL);
    }

    env = getenv("SH_PROFILE_ONLINE_STRAT_ORIG");
    profopts.profile_online_orig = 0;
    if(env) {
      profopts.profile_online_orig = 1;
    }

    if(profopts.profile_online_orig) {
      /* Orig-specific configuration */

      env = getenv("SH_PROFILE_ONLINE_RECONF_WEIGHT_RATIO");
      profopts.profile_online_reconf_weight_ratio = 0.0;
      if(env) {
        profopts.profile_online_reconf_weight_ratio = strtof(env, NULL);
      }

      env = getenv("SH_PROFILE_ONLINE_HOT_INTERVALS");
      profopts.profile_online_hot_intervals = 0;
      if(env) {
        profopts.profile_online_hot_intervals = strtoul(env, NULL, 0);
      }
    }

    env = getenv("SH_PROFILE_ONLINE_STRAT_SKI");
    profopts.profile_online_ski = 0;
    if(env) {
      profopts.profile_online_ski = 1;
    }
  }
  if(tracker.log_file) {
    fprintf(tracker.log_file, "SH_PROFILE_ONLINE: %d\n", should_profile_online());
    fprintf(tracker.log_file, "SH_PROFILE_ONLINE_SKIP_INTERVALS: %d\n", profopts.profile_online_skip_intervals);
    fprintf(tracker.log_file, "SH_PROFILE_ONLINE_USE_LAST_INTERVAL: %d\n", profopts.profile_online_use_last_interval);
    fprintf(tracker.log_file, "SH_PROFILE_ONLINE_GRACE_ACCESSES: %lu\n", profopts.profile_online_grace_accesses);
  }

  /* Get the arena layout */
  env = getenv("SH_ARENA_LAYOUT");
  if(env) {
    tracker.layout = parse_layout(env);
  } else {
    tracker.layout = DEFAULT_ARENA_LAYOUT;
  }
  if(tracker.log_file) {
    fprintf(tracker.log_file, "SH_ARENA_LAYOUT: %s\n", env);
  }

  /* Get the threshold for a "big" or "small" arena, in bytes */
  if(tracker.layout == BIG_SMALL_ARENAS) {
    env = getenv("SH_BIG_SMALL_THRESHOLD");
    if(env) {
      tracker.big_small_threshold = strtoul(env, NULL, 0);
    }
    if(tracker.log_file) {
      fprintf(tracker.log_file, "SH_BIG_SMALL_THRESHOLD: %lu\n", tracker.big_small_threshold);
    }
  }

  /* Get max_threads */
  tracker.max_threads = numa_num_possible_cpus();
  env = getenv("SH_MAX_THREADS");
  if(env) {
    tmp_val = strtoimax(env, NULL, 10);
    if((tmp_val == 0) || (tmp_val > INT_MAX)) {
      fprintf(stderr, "Invalid thread number given. Aborting.\n");
      exit(1);
    } else {
      tracker.max_threads = (int) tmp_val;
    }
  }
  if(tracker.log_file) {
    fprintf(tracker.log_file, "SH_MAX_THREADS: %d\n", tracker.max_threads);
  }

  /* Get max_arenas.
   * Keep in mind that 4095 is the maximum number supported by jemalloc
   * (12 bits to store the arena IDs, minus one).
   * An error occurs if this limit is reached.
   */
  tracker.max_arenas = 4095;
  env = getenv("SH_MAX_ARENAS");
  if(env) {
    tmp_val = strtoimax(env, NULL, 10);
    if((tmp_val == 0) || (tmp_val > INT_MAX)) {
      fprintf(stderr, "Invalid arena number given. Aborting.\n");
      exit(1);
    } else {
      tracker.max_arenas = (int) tmp_val;
    }
  }
  if(tracker.log_file) {
    fprintf(tracker.log_file, "SH_MAX_ARENAS: %d\n", tracker.max_arenas);
  }

  /* Get max_sites_per_arena.
   * This is the maximum amount of allocation sites that a single arena can hold.
   */
  tracker.max_sites_per_arena = 1;
  env = getenv("SH_MAX_SITES_PER_ARENA");
  if(env) {
    tmp_val = strtoimax(env, NULL, 10);
    if((tmp_val == 0) || (tmp_val > INT_MAX)) {
      fprintf(stderr, "Invalid arena number given. Aborting.\n");
      exit(1);
    } else {
      tracker.max_sites_per_arena = (int) tmp_val;
    }
  }
  if(tracker.log_file) {
    fprintf(tracker.log_file, "SH_MAX_SITES_PER_ARENA: %d\n", tracker.max_sites_per_arena);
  }
  
  /* Get max_sites.
     This is the maximum number of allocation sites that you can have. Keep in mind
     that we use site IDs as indices into an array, so the maximum site ID that you can
     have is `tracker.max_sites - 1`. */
  tracker.max_sites = 4096;
  env = getenv("SH_MAX_SITES");
  if(env) {
    tmp_val = strtoimax(env, NULL, 10);
    if((tmp_val == 0) || (tmp_val > INT_MAX)) {
      fprintf(stderr, "Invalid arena number given. Aborting.\n");
      exit(1);
    } else {
      tracker.max_sites = (int) tmp_val;
    }
  }
  if(tracker.log_file) {
    fprintf(tracker.log_file, "SH_MAX_SITES: %d\n", tracker.max_sites);
  }

  /* Controls the profiling rate of all profiling types */
  profopts.profile_rate_nseconds = 0;
  env = getenv("SH_PROFILE_RATE_NSECONDS");
  if(env) {
    profopts.profile_rate_nseconds = strtoimax(env, NULL, 10);
  }
  if(tracker.log_file) {
    fprintf(tracker.log_file, "SH_PROFILE_RATE_NSECONDS: %zu\n", profopts.profile_rate_nseconds);
  }

  /* The user can specify a number of NUMA nodes to profile on. For profile_all,
     all CPUs on the node(s) will be profiled. For profile_bw, one CPU from
     each node will be chosen to record the bandwidth on the IMC. */
  env = getenv("SH_PROFILE_NODES");
  profopts.num_profile_all_cpus = 0;
  profopts.num_profile_skt_cpus = 0;
  profopts.profile_all_cpus = NULL;
  profopts.profile_skt_cpus = NULL;
  profopts.profile_skts = NULL;
  if(env) {
    /* First, get a list of nodes that the user specified */
    nodes = numa_parse_nodestring(env);
    cpus = numa_allocate_cpumask();
    num_cpus = numa_num_configured_cpus();
    num_nodes = numa_num_configured_nodes();
    /* Iterate over the nodes in the `nodes` bitmask */
    for(node = 0; node < num_nodes; node++) {
      if(numa_bitmask_isbitset(nodes, node)) {
        numa_bitmask_clearall(cpus);
        numa_node_to_cpus(node, cpus);
        flag = 0;
        /* Now iterate over the CPUs on those nodes */
        for(cpu = 0; cpu < num_cpus; cpu++) {
          if(numa_bitmask_isbitset(cpus, cpu)) {
            /* Here, we'll add one (1) CPU from this list to profile_skt_cpus */
            if(!flag) {
              profopts.num_profile_skt_cpus++;
              profopts.profile_skt_cpus = orig_realloc(profopts.profile_skt_cpus,
                                                      sizeof(int) * profopts.num_profile_skt_cpus);
              profopts.profile_skts = orig_realloc(profopts.profile_skt_cpus,
                                                       sizeof(int) * profopts.num_profile_skt_cpus);
              profopts.profile_skt_cpus[profopts.num_profile_skt_cpus - 1] = cpu;
              profopts.profile_skts[profopts.num_profile_skt_cpus - 1] = node;
              flag = 1;
            }
            /* ...and add all of the CPUs to profile_all */
            profopts.num_profile_all_cpus++;
            profopts.profile_all_cpus = orig_realloc(profopts.profile_all_cpus, sizeof(int) * profopts.num_profile_all_cpus);
            profopts.profile_all_cpus[profopts.num_profile_all_cpus - 1] = cpu;
          }
        }
      }
    }
  } else {
    /* If the user doesn't set this, default to using the CPUs on the NUMA nodes that this
        process is allowed on */
    cpus = numa_all_cpus_ptr;
    num_cpus = numa_num_configured_cpus();
    flag = 0;
    for(cpu = 0; cpu < num_cpus; cpu++) {
      if(numa_bitmask_isbitset(cpus, cpu)) {
        if(!flag) {
          profopts.num_profile_skt_cpus++;
          profopts.profile_skt_cpus = orig_realloc(profopts.profile_skt_cpus,
                                                  sizeof(int) * profopts.num_profile_skt_cpus);
          profopts.profile_skts = orig_realloc(profopts.profile_skts,
                                                  sizeof(int) * profopts.num_profile_skt_cpus);
          profopts.profile_skt_cpus[profopts.num_profile_skt_cpus - 1] = cpu;
          profopts.profile_skts[profopts.num_profile_skt_cpus - 1] = numa_node_of_cpu(cpu);
          flag = 1;
        }
        profopts.num_profile_all_cpus++;
        profopts.profile_all_cpus = orig_realloc(profopts.profile_all_cpus, sizeof(int) * profopts.num_profile_all_cpus);
        profopts.profile_all_cpus[profopts.num_profile_all_cpus - 1] = cpu;
      }
    }
  }

  /* Should we profile all allocation sites using sampling-based profiling? */
  env = getenv("SH_PROFILE_ALL");
  if(env) {
    enable_profile_all();
  }
  if(should_profile_all()) {

    env = getenv("SH_PROFILE_ALL_EVENTS");
    profopts.num_profile_all_events = 0;
    profopts.profile_all_events = NULL;
    if(env) {
      /* Parse out the events into an array */
      while((str = strtok(env, ",")) != NULL) {
        profopts.num_profile_all_events++;
        profopts.profile_all_events = orig_realloc(profopts.profile_all_events, sizeof(char *) * profopts.num_profile_all_events);
        profopts.profile_all_events[profopts.num_profile_all_events - 1] = orig_malloc(sizeof(char) * (strlen(str) + 1));
        strcpy(profopts.profile_all_events[profopts.num_profile_all_events - 1], str);
        env = NULL;
      }
    }
    if(profopts.num_profile_all_events == 0) {
      fprintf(stderr, "No profiling events given. Can't profile with sampling.\n");
      exit(1);
    }
    
    env = getenv("SH_PROFILE_ALL_MULTIPLIERS");
    profopts.num_profile_all_multipliers = 0;
    profopts.profile_all_multipliers = NULL;
    if(env) {
      /* Parse out the events into an array */
      while((str = strtok(env, ",")) != NULL) {
        profopts.num_profile_all_multipliers++;
        profopts.profile_all_multipliers = orig_realloc(profopts.profile_all_multipliers, sizeof(float) * profopts.num_profile_all_multipliers);
        profopts.profile_all_multipliers[profopts.num_profile_all_multipliers - 1] = strtof(str, NULL);
        env = NULL;
      }
      if(profopts.num_profile_all_multipliers != profopts.num_profile_all_events) {
        fprintf(stderr, "Number of multipliers doesn't equal the number of PROFILE_ALL events. Aborting.\n");
        exit(1);
      }
    }

    env = getenv("SH_PROFILE_ALL_SKIP_INTERVALS");
    profopts.profile_all_skip_intervals = 1;
    if(env) {
      profopts.profile_all_skip_intervals = strtoul(env, NULL, 0);
    }

    if(tracker.log_file) {
      fprintf(tracker.log_file, "SH_PROFILE_ALL: %d\n", should_profile_all());
      fprintf(tracker.log_file, "SH_PROFILE_ALL_SKIP_INTERVALS: %lu\n", profopts.profile_all_skip_intervals);
      fprintf(tracker.log_file, "NUM_PROFILE_ALL_EVENTS: %zu\n", profopts.num_profile_all_events);
      for(i = 0; i < profopts.num_profile_all_events; i++) {
        fprintf(tracker.log_file, "PROFILE_ALL_EVENTS: %s\n", profopts.profile_all_events[i]);
      }
    }

    env = getenv("SH_TRACK_PAGES");
    profopts.track_pages = 0;
    if(env) {
      profopts.track_pages = 1;
      if(tracker.log_file) {
        fprintf(tracker.log_file, "SH_TRACK_PAGES: %zu\n", profopts.track_pages);
      }
    }

    env = getenv("SH_PAGE_PROFILE_INTERVALS");
    profopts.page_profile_intervals = 0;
    if(env) {
      profopts.page_profile_intervals = 1;
    }

    if(tracker.log_file) {
      fprintf(tracker.log_file, "SH_PAGE_PROFILE_INTERVALS: %zu\n", profopts.page_profile_intervals);
    }

    env = getenv("SH_TRACK_CACHE_BLOCKS");
    profopts.track_cache_blocks = 0;
    if(env) {
      profopts.track_cache_blocks = 1;
    }

    if(tracker.log_file) {
      fprintf(tracker.log_file, "SH_TRACK_CACHE_BLOCKS: %zu\n", profopts.track_cache_blocks);
    }

    env = getenv("SH_CACHE_BLOCK_PROFILE_INTERVALS");
    profopts.cache_block_profile_intervals = 0;
    if(env) {
      profopts.cache_block_profile_intervals = 1;
    }

    if(tracker.log_file) {
      fprintf(tracker.log_file, "SH_CACHE_BLOCK_PROFILE_INTERVALS: %zu\n", profopts.cache_block_profile_intervals);
    }
  }

  /* Should we keep track of when each allocation happened, in intervals? */
  env = getenv("SH_PRINT_PER_INTERVAL_PROFILE");
  profopts.print_per_interval_profile = 0;
  if(env) {
    profopts.print_per_interval_profile = 1;
  }
  if(tracker.log_file) {
    fprintf(tracker.log_file, "SH_PRINT_PER_INTERVAL_PROFILE: %d\n",
      profopts.print_per_interval_profile);
  }

  /* Should we keep track of when each allocation happened, in intervals? */
  env = getenv("SH_PROFILE_ALLOCS");
  if(env) {
    enable_profile_allocs();
  }
  if(tracker.log_file) {
    fprintf(tracker.log_file, "SH_PROFILE_ALLOCS: %d\n", should_profile_allocs());
  }

  /* Should we keep track of when each object and its site ID */
  env = getenv("SH_PROFILE_OBJECTS");
  profopts.should_profile_objects = 0;
  if(env) {
    profopts.should_profile_objects = 1;
  }
  if(tracker.log_file) {
    fprintf(tracker.log_file, "SH_PROFILE_OBJECTS: %d\n", profopts.should_profile_objects);
  }
 
  /* The user should specify a comma-delimited list of IMCs to read the
    * bandwidth from. This will be passed to libpfm. For example, on an Ivy
    * Bridge server, this value is e.g. `ivbep_unc_imc0`, and on KNL it's
    * `knl_unc_imc0`. These are per-socket IMCs, so they will be used on all
    * sockets that you choose to profile on.
    */
  env = getenv("SH_PROFILE_IMC");
  profopts.num_imcs = 0;
  profopts.imcs = NULL;
  if(env) {
    /* Parse out the IMCs into an array */
    while((str = strtok(env, ",")) != NULL) {
      profopts.num_imcs++;
      profopts.imcs = orig_realloc(profopts.imcs, sizeof(char *) * profopts.num_imcs);
      profopts.imcs[profopts.num_imcs - 1] = str;
      env = NULL;
    }
  }
  
  /* Should we profile bandwidth on a specific socket? */
  env = getenv("SH_PROFILE_BW");
  profopts.profile_bw_skip_intervals = 0;
  if(env) {
    enable_profile_bw();
    
    if(profopts.num_imcs == 0) {
      fprintf(stderr, "No IMCs given. Can't enable profile_bw.\n");
      exit(1);
    }

    env = getenv("SH_PROFILE_BW_SKIP_INTERVALS");
    profopts.profile_bw_skip_intervals = 1;
    if(env) {
      profopts.profile_bw_skip_intervals = strtoul(env, NULL, 0);
    }
    
    /* The user should specify a number of CPUs to use to read
       the bandwidth from the IMCs. In the case of many machines,
       this usually means that the user should select one CPU per socket. */
    
    /*
    What events should be used to measure the bandwidth?
     */
    env = getenv("SH_PROFILE_BW_EVENTS");
    profopts.num_profile_bw_events = 0;
    profopts.profile_bw_events = NULL;
    if(env) {
      /* Parse out the events into an array */
      while((str = strtok(env, ",")) != NULL) {
        profopts.num_profile_bw_events++;
        profopts.profile_bw_events = orig_realloc(profopts.profile_bw_events, sizeof(char *) * profopts.num_profile_bw_events);
        profopts.profile_bw_events[profopts.num_profile_bw_events - 1] = malloc(sizeof(char) * (strlen(str) + 1));
        strcpy(profopts.profile_bw_events[profopts.num_profile_bw_events - 1], str);
        env = NULL;
      }
    }
    if(profopts.num_profile_bw_events == 0) {
      fprintf(stderr, "No profiling events given. Can't profile one arena.\n");
      exit(1);
    }
    
    /* Should we try to associate bandwidth with arenas, using their
       relative profile_all values? */
    env = getenv("SH_PROFILE_BW_RELATIVE");
    profopts.profile_bw_relative = 0;
    if(env) {
      profopts.profile_bw_relative = 1;
    }
  }
  if(tracker.log_file) {
    fprintf(tracker.log_file, "SH_PROFILE_BW: %d\n", should_profile_bw());
  }
  
  /* Should we profile latency on a specific socket? */
  env = getenv("SH_PROFILE_LATENCY");
  profopts.profile_latency_skip_intervals = 0;
  if(env) {
    enable_profile_latency();
    
    if(profopts.num_imcs == 0) {
      fprintf(stderr, "No IMCs given. Can't enable profile_latency.\n");
      exit(1);
    }
    
    env = getenv("SH_PROFILE_LATENCY_SET_MULTIPLIERS");
    profopts.profile_latency_set_multipliers = 0;
    if(env) {
      profopts.profile_latency_set_multipliers = 1;
    }

    env = getenv("SH_PROFILE_LATENCY_SKIP_INTERVALS");
    profopts.profile_latency_skip_intervals = 1;
    if(env) {
      profopts.profile_latency_skip_intervals = strtoul(env, NULL, 0);
    }
    
    /*
      What events should be used to measure the latency?
    */
    env = getenv("SH_PROFILE_LATENCY_EVENTS");
    profopts.num_profile_latency_events = 0;
    profopts.profile_latency_events = NULL;
    if(env) {
      /* Parse out the events into an array */
      while((str = strtok(env, ",")) != NULL) {
        profopts.num_profile_latency_events++;
        profopts.profile_latency_events = orig_realloc(profopts.profile_latency_events, sizeof(char *) * profopts.num_profile_latency_events);
        profopts.profile_latency_events[profopts.num_profile_latency_events - 1] = malloc(sizeof(char) * (strlen(str) + 1));
        strcpy(profopts.profile_latency_events[profopts.num_profile_latency_events - 1], str);
        env = NULL;
      }
      if(profopts.num_profile_latency_events != 8) {
        fprintf(stderr, "Currently, the profile_latency profiler hardcodes a metric composed of exactly eight (read and write) events.\n");
        fprintf(stderr, "The first four should be for the upper tier, and the last four should be for the lower tier.\n");
        fprintf(stderr, "Aborting.\n");
        exit(1);
      }
    }
    if(profopts.num_profile_latency_events == 0) {
      fprintf(stderr, "No profiling events given. Can't profile latency.\n");
      exit(1);
    }
    
    /*
      We'll need an event to measure the DRAM clockticks
    */
    env = getenv("SH_PROFILE_LATENCY_CLOCKTICK_EVENT");
    profopts.profile_latency_clocktick_event = NULL;
    if(env) {
      profopts.profile_latency_clocktick_event = malloc(sizeof(char) * (strlen(env) + 1));
      strcpy(profopts.profile_latency_clocktick_event, env);
    }
    if(profopts.profile_latency_clocktick_event == NULL) {
      fprintf(stderr, "Need an event to get clockticks from the DRAM. Can't profile latency. Aborting.\n");
      exit(1);
    }
  }

  /* Should we get the RSS of each arena? */
  env = getenv("SH_PROFILE_RSS");
  profopts.profile_rss_skip_intervals = 0;
  if(env) {
    enable_profile_rss();

    env = getenv("SH_PROFILE_RSS_SKIP_INTERVALS");
    profopts.profile_rss_skip_intervals = 1;
    if(env) {
      profopts.profile_rss_skip_intervals = strtoul(env, NULL, 0);
    }
  }
  if(tracker.log_file) {
    fprintf(tracker.log_file, "SH_PROFILE_RSS: %d\n", profopts.should_profile_rss);
    fprintf(tracker.log_file, "SH_PROFILE_RSS_SKIP_INTERVALS: %d\n", profopts.profile_rss_skip_intervals);
  }

  env = getenv("SH_PROFILE_EXTENT_SIZE");
  if(env) {
    enable_profile_extent_size();

    env = getenv("SH_PROFILE_EXTENT_SIZE_SKIP_INTERVALS");
    profopts.profile_extent_size_skip_intervals = 1;
    if(env) {
      profopts.profile_extent_size_skip_intervals = strtoul(env, NULL, 0);
    }
  }

  env = getenv("SH_PROFILE_ALLOCS");
  if(env) {
    enable_profile_allocs();

    env = getenv("SH_PROFILE_ALLOCS_SKIP_INTERVALS");
    profopts.profile_allocs_skip_intervals = 1;
    if(env) {
      profopts.profile_allocs_skip_intervals = strtoul(env, NULL, 0);
    }
  }


  /* Should we get the dirty of each arena? */
  env = getenv("SH_PROFILE_DIRTY");
  profopts.should_profile_dirty = 0;
  profopts.profile_dirty_skip_intervals = 0;
  if(env) {
    profopts.should_profile_dirty = 1;

    env = getenv("SH_PROFILE_DIRTY_SKIP_INTERVALS");
    profopts.profile_dirty_skip_intervals = 1;
    if(env) {
      profopts.profile_dirty_skip_intervals = strtoul(env, NULL, 0);
    }
  }

  /* What sample frequency should we use? Default is 2048. Higher
   * frequencies will fill up the sample pages (below) faster.
   */
  env = getenv("SH_SAMPLE_FREQ");
  profopts.sample_freq = 2048;
  if(env) {
    tmp_val = strtoimax(env, NULL, 10);
    if((tmp_val <= 0)) {
      fprintf(stderr, "Invalid sample frequency given: %d. Aborting.\n", tmp_val);
      exit(1);
    } else {
      profopts.sample_freq = (int) tmp_val;
    }
  }

#if 0
  /* How many samples should be collected by perf, maximum?
   * Assuming we're only tracking addresses, this number is multiplied by
   * the page size and divided by 16 to get the maximum number of samples.
   * 8 of those bytes are the header, and the other 8 are the address itself.
   * By default this is 64 pages, which yields 16k samples.
   */
  env = getenv("SH_MAX_SAMPLE_PAGES");
  profopts.max_sample_pages = 64;
  if(env) {
    tmp_val = strtoimax(env, NULL, 10);
    /* Value needs to be non-negative, less than or equal to 512, and a power of 2. */
    if((tmp_val <= 0) || (tmp_val > 2048) || (tmp_val & (tmp_val - 1))) {
      fprintf(stderr, "Invalid number of pages given. Aborting.\n");
      exit(1);
    } else {
      profopts.max_sample_pages = (int) tmp_val;
    }
  }
#endif
#if 1
  env = getenv("SH_MAX_SAMPLE_PAGES");
  profopts.max_sample_pages = 64;
  if(env) {
    tmp_val = strtoimax(env, NULL, 10);
    /* Value needs to be non-negative and a power of 2. */
    if((tmp_val <= 0) || (tmp_val & (tmp_val - 1))) {
      fprintf(stderr, "Invalid number of pages given. Aborting.\n");
      exit(1);
    } else {
      profopts.max_sample_pages = (int) tmp_val;
    }
  }
#endif

  /* Get the devices */
  env = getenv("SH_UPPER_NODE");
  tracker.upper_device = NULL;
  if(env) {
    tmp_val = strtoimax(env, NULL, 10);
    tracker.upper_device = get_device_from_numa_node((int) tmp_val);
  }
  if(!tracker.upper_device) {
    fprintf(stderr, "WARNING: Upper device defaulting to NUMA node 0.\n");
    tracker.upper_device = get_device_from_numa_node(0);
  }
  env = getenv("SH_LOWER_NODE");
  tracker.lower_device = NULL;
  if(env) {
    tmp_val = strtoimax(env, NULL, 10);
    tracker.lower_device = get_device_from_numa_node((int) tmp_val);
  }
  if(!tracker.lower_device) {
    fprintf(stderr, "WARNING: Lower device defaulting to NUMA node 0.\n");
    tracker.lower_device = get_device_from_numa_node(0);
  }
  env = getenv("SH_DEFAULT_NODE");
  tracker.default_device = NULL;
  if(env) {
    tmp_val = strtoimax(env, NULL, 10);
    tracker.default_device = get_device_from_numa_node((int) tmp_val);
  }
  if(!tracker.default_device) {
    tracker.default_device = tracker.lower_device;
  }
  if(tracker.log_file) {
    fprintf(tracker.log_file, "SH_DEFAULT_NODE: %d\n", sicm_numa_id(tracker.default_device));
    fprintf(tracker.log_file, "SH_UPPER_NODE: %d\n", sicm_numa_id(tracker.upper_device));
    fprintf(tracker.log_file, "SH_LOWER_NODE: %d\n", sicm_numa_id(tracker.lower_device));
  }

  /* Get arenas_per_thread */
  switch(tracker.layout) {
    case EXCLUSIVE_ARENAS:
      tracker.arenas_per_thread = 1;
      break;
    case EXCLUSIVE_DEVICE_ARENAS:
      tracker.arenas_per_thread = 2;
      break;
    case SHARED_SITE_ARENAS:
    case BIG_SMALL_ARENAS:
      tracker.arenas_per_thread = 1;
    default:
      tracker.arenas_per_thread = 1;
      break;
  };

  /* Get the guidance file that tells where each site goes */
  env = getenv("SH_GUIDANCE_FILE");
  if(env) {
    /* Open the file */
    guidance_file = fopen(env, "r");
    if(!guidance_file) {
      fprintf(stderr, "Failed to open guidance file. Aborting.\n");
      exit(1);
    }

    /* Read in the sites */
    guidance = 0;
    found_guidance = 0; /* Set if we find any site guidance at all */
    line = NULL;
    len = 0;
    while(getline(&line, &len, guidance_file) != -1) {
      str = strtok(line, " ");
      if(guidance) {
        if(!str) continue;

        /* Look to see if it's the end */
        if(str && (strcmp(str, "=====") == 0)) {
          str = strtok(NULL, " ");
          if(str && (strcmp(str, "END") == 0)) {
            guidance = 0;
          } else {
            fprintf(stderr, "In a guidance section, and found five equals signs, but not the end. Aborting.\n");
            exit(1);
          }
          continue;
        }

        /* Read in the actual guidance now that we're in a guidance section */
        sscanf(str, "%d", &site);
        str = strtok(NULL, " ");
        if(!str) {
          fprintf(stderr, "Read in a site number from the guidance file, but no node number. Aborting.\n");
          exit(1);
        }
        sscanf(str, "%d", &node);

        /* Use the arrays of atomics to set this site to go to the proper device */
        tracker.site_devices[site] = (atomic_intptr_t) get_device_from_numa_node(node);
        
      } else {
        if(!str) continue;
        /* Find the "===== GUIDANCE" tokens */
        if(strcmp(str, "=====") != 0) continue;
        str = strtok(NULL, " ");
        if(str && (strcmp(str, "GUIDANCE") == 0)) {
          /* Now we're in a guidance section */
          guidance = 1;
          found_guidance = 1;
          continue;
        }
      }
    }
    if(!found_guidance) {
      fprintf(stderr, "Didn't find any guidance in the file. Aborting.\n");
      exit(1);
    }
  }

  env = getenv("SH_NUM_STATIC_SITES");
  if (env) {
    tmp_val = strtoimax(env, NULL, 10);
    if((tmp_val == 0) || (tmp_val > INT_MAX)) {
      fprintf(stderr, "Invalid number of static sites given. Aborting.\n");
      exit(1);
    } else {
      tracker.num_static_sites = (int) tmp_val;
    }
  }

  env = getenv("SH_RDSPY");
  profopts.should_run_rdspy = 0;
  if (env) {
    if (!tracker.num_static_sites) {
      fprintf(stderr, "Invalid number of static sites. Aborting.\n");
      exit(1);
    }
    profopts.should_run_rdspy = 1 && tracker.num_static_sites;
  }
  
  printf("profile_type_flags = %u\n", profopts.profile_type_flags);
  if(should_profile_online()) {
    printf("I should profile online.\n");
  }
  fflush(stdout);
}

__attribute__((constructor))
void sh_init() {
  int i;
  long size;

  if(sh_initialized) {
    /* We already initialized, don't do it again. */
    fprintf(stderr, "sh_initialized called twice.\n");
    fflush(stderr);
    return;
  }

  fprintf(stderr, "Beginning initialization.\n");
  fflush(stderr);

  orig_malloc_ptr = dlsym(RTLD_NEXT, "malloc");
  orig_calloc_ptr = dlsym(RTLD_NEXT, "calloc");
  orig_realloc_ptr = dlsym(RTLD_NEXT, "realloc");
  orig_free_ptr = dlsym(RTLD_NEXT, "free");

  fprintf(stderr, "Initializing SICM.\n");
  fflush(stderr);

  tracker.device_list = sicm_init();

  fprintf(stderr, "Initialized SICM.\n");
  fflush(stderr);

  /* Initialize all of the locks */
  pthread_rwlock_init(&tracker.extents_lock, NULL);
  pthread_mutex_init(&tracker.arena_lock, NULL);
  pthread_rwlock_init(&tracker.device_arenas_lock, NULL);

  /* Get the number of NUMA nodes with memory, since we ignore huge pages with
   * the DEVICE arena layouts */
  tracker.num_numa_nodes = 0;
  for(i = 0; i <= numa_max_node(); i++) {
    size = -1;
    if ((numa_node_size(i, &size) != -1) && size) {
      tracker.num_numa_nodes++;
    }
  }

  tracker.arena_counter = 0;
  set_options();

  if(tracker.layout != INVALID_LAYOUT) {
    tracker.arenas = (arena_info **) orig_calloc(tracker.max_arenas, sizeof(arena_info *));
    
    /* These atomics keep track of per-site information, such as:
       1. `site_bigs`: boolean for if the site is above big_small_threshold or not.
       2. `site_sizes`: the number of bytes allocated to this site.
       3. `site_devices`: a pointer to the device that this site should be bound to.
       4. `site_arenas`: an integer index of the arena this site gets allocated to.
    */
    tracker.site_bigs = (atomic_char *) orig_calloc(tracker.max_sites, sizeof(atomic_char));
    tracker.site_sizes = (atomic_size_t *) orig_calloc(tracker.max_sites, sizeof(atomic_size_t));
    tracker.site_devices = (atomic_intptr_t *) orig_malloc(tracker.max_sites * sizeof(atomic_intptr_t));
    for(i = 0; i < tracker.max_sites; i++) {
      tracker.site_devices[i] = (atomic_intptr_t) NULL;
    }
    tracker.site_arenas = (atomic_int *) orig_malloc(tracker.max_sites * sizeof(atomic_int));
    for(i = 0; i < tracker.max_sites; i++) {
      tracker.site_arenas[i] = -1;
    }

    /* Initialize the extents array.
     */
    tracker.extents = extent_arr_init();
    
    /* This is just an atomic counter that we use to grab a new
       index for every thread that allocates for the first time */
    tracker.current_thread_index = 0;
    
    if(should_profile_all() ||
       should_profile_rss() ||
       should_profile_extent_size()) {
      /* Set the arena allocator's callback function */
      sicm_extent_alloc_callback = &sh_create_extent;
      sicm_extent_dalloc_callback = &sh_delete_extent;
    }

    if(should_profile()) {
      sh_start_profile_master_thread();
    }
  }

  if (profopts.should_run_rdspy) {
    sh_rdspy_init(tracker.max_threads, tracker.num_static_sites);
  }

  if(tracker.log_file) {
    fprintf(tracker.log_file, "===== END OPTIONS =====\n");
    //fclose(tracker.log_file);
  }

  sh_initialized = 1;

  fprintf(stderr, "Finished initialization.\n");
  fflush(stderr);
}

__attribute__((destructor))
void sh_terminate() {
  size_t i;
  arena_info *arena;
  int err;
  bool on;

  if(!sh_initialized) {
    return;
  }
  sh_initialized = 0;
  
  if(tracker.log_file) {
    fclose(tracker.log_file);
  }

  /* Disable the background thread in jemalloc to avoid a segfault */
  on = false;
  err = je_mallctl("background_thread", NULL, NULL, (void *)&on, sizeof(bool));
  if(err) {
    fprintf(stderr, "Failed to disable background threads: %d\n", err);
    exit(1);
  }

  if(tracker.layout != INVALID_LAYOUT) {

    /* Clean up the profiler */
    if(should_profile()) {
      sh_stop_profile_master_thread();
    }

    /* Clean up the arenas */
    arena_arr_for(i) {
      arena_check_good(arena, i);

      sicm_arena_destroy(tracker.arenas[i]->arena);
      orig_free(tracker.arenas[i]);
    }
    orig_free(tracker.arenas);
    extent_arr_free(tracker.extents);
  }

  /* Clean up the low-level interface */
  sicm_fini(&tracker.device_list);


  if(profopts.should_run_rdspy) {
    sh_rdspy_terminate();
  }
}
