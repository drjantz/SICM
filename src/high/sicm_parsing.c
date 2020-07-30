#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <errno.h>

#include "sicm_parsing.h"

void get_pfn(int pagemap_fd, addr_t vaddr, region_profile_ptr page_rec) {
  union pfn_t pfndata;
  size_t pagesize, addrsize;
  int bytes_read;

  pagesize = (1<<PAGE_SHIFT);
  addrsize = sizeof(uint64_t);

  pthread_mutex_lock(&tracker.pagemap_lock);
  if( lseek64(pagemap_fd, (((uint64_t)vaddr) / pagesize) * addrsize, SEEK_SET) ==
      ((__off64_t) - 1) ) {
    close(pagemap_fd);
    fprintf(stderr, "Failed to seek in the PageMap file. Aborting.\n");
    exit(1);
  }

  bytes_read = read(pagemap_fd, &pfndata, addrsize);
  pthread_mutex_unlock(&tracker.pagemap_lock);

  if(bytes_read == -1) {
    fprintf(stderr, "Failed to read from PageMap file. Aborting: %d, %s\n", errno, strerror(errno));
    exit(1);
  } else if(bytes_read < addrsize) {
    fprintf(stderr, "WARNING: get_pfn read less bytes than expected.\n");
  } else {
    if (pfndata.obj.present) {
      page_rec->pfn = pfndata.obj.pfn;
    }
  }
}

void get_page_map_pfns(tree(addr_t, region_profile_ptr) page_map) {
  int pagemap_fd;
  tree_it(addr_t, region_profile_ptr) it;

  pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
  if (pagemap_fd < 0) {
    fprintf(stderr, "Failed to open /proc/self/pagemap. Aborting.\n");
    exit(1);
  }

  tree_traverse(page_map, it) {
    if (tree_it_good(it)) {
      get_pfn(pagemap_fd, tree_it_key(it), tree_it_val(it));
    }
  }

  close(pagemap_fd);
}

