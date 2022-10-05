#include <stdio.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>

#define BLOCK_SZ 4096

off_t get_file_size(int fd) {
    struct stat st;

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }
    if (S_ISBLK(st.st_mode)) {
        unsigned long long bytes;
	if (ioctl(fd, BLKGETSIZE64, &bytes) != 0) {
            perror("ioctl");
	    return -1;
	}
    } else if (S_ISREG(st.st_mode))
        return st.st_size;

    return -1;
}

void output_to_console(char *buf, int len) {
    while (len--)
        fputc(*buf++, stdout);
}

int read_and_print_file(char *file_name) {
    struct iovec *iovecs;
    int file_fd = open(file_name, O_RDONLY);
    if (file_fd < 0) {
        perror("open");
	return 1;
    }
    
    off_t file_sz = get_file_size(file_fd);
    off_t bytes_remaining = file_sz;
    int blocks = (int) file_sz / BLOCK_SZ;
    if (file_sz % BLOCK_SZ) blocks++;
    iovecs = malloc(sizeof(struct iovec) * blocks);

    int current_block = 0;

    while (bytes_remaining) {
        off_t bytes_to_read = bytes_remaining;
	if (bytes_to_read > BLOCK_SZ)
	    bytes_to_read = BLOCK_SZ;

	void *buf;
	if( posix_memalign(&buf, BLOCK_SZ, BLOCK_SZ)) {
	    perror("posix_memallign");
	    return -1;
	}
	iovecs[current_block].iov_base = buf;
	iovecs[current_block].iov_len = bytes_to_read;
	current_block++;
	bytes_remaining -= bytes_to_read;
    }

    int ret = readv(file_fd, iovecs, blocks);
    if (ret < 0) {
	perror("readv");
	return 1;
    }
    
    for (int i = 0; i < blocks; i++)
	output_to_console(iovecs[i].iov_base, iovecs[i].iov_len);

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename1> [<filename2>]\n", argv[0]);
    }

    for (int i = 1; i < argc; i++) {
        if (read_and_print_file(argv[i])) {
            fprintf(stderr, "Error reading file\n");
	    return 1;
	}
    }

    return 0;
}
