#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

#endif /* userprog/syscall.h */

#include <stdbool.h>

typedef int pid_t;


void halt(void);

void exit(int status);

pid_t exec(const char *cmd_line);

int wait(pid_t pid);

bool create (const char *file, unsigned initial_size);

bool remove(const char *file);

int open(const char *file);

int filesize(int fd);

int read(int fd, void *buffer, unsigned size);

int write(int fd, const void *buffer, unsigned size);

void seek(int fd, unsigned position);

unsigned tell(int fd);

void close(int fd);

struct file* get_opened_file_with_fd(int fd);

void remove_all_opened_files(void);

