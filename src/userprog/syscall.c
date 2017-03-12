#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

// These includes are for file system operations
#include "filesys/file.h"
#include "filesys/filesys.h"

// This include is for synchronization "lock"
#include "threads/synch.h"

// This include is for using input_getc() when fd = STDIN_FILENO in read syscall
#include "devices/input.h"


#include "threads/init.h"
#include "threads/vaddr.h"
#include <stdbool.h>
#define Max_arg 3
#define WORD_SIZE 4

#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define FAILURE -1

static void syscall_handler (struct intr_frame *);
static struct lock filesys_syscalls_lock;
int arguments[] = {0,1,1,1,2,1,1,1,3,3,2,1,1,1,0};
static uint32_t *esp;

void
syscall_init (void) 
{
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
	lock_init (&filesys_syscalls_lock);
}

void 
check_addr(uint32_t *stack_pointer){
	if (stack_pointer == NULL){
		exit(-1);

	}else if (!is_user_vaddr(stack_pointer)){
		exit(-1);
	}

	uint32_t *pd = thread_current()->pagedir;
    void* kernel_virtual_address = pagedir_get_page (pd, stack_pointer);
    if (kernel_virtual_address == NULL)
    {
        exit(-1);
    }
}

bool
is_valid_pointer (const void *usr_ptr)
{
	if(usr_ptr != NULL && is_user_vaddr (usr_ptr)){
		if (pagedir_get_page(thread_current()->pagedir, usr_ptr) != NULL)
		{
			return true;
		}
		else
		{
  		 	return false;
  		}
  	}
	return false;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{ 
  esp = f->esp;
  check_addr(esp);
  int syscall_num = *esp;
         int i= 0 ;

  for(int i =1 ;i<=arguments[syscall_num]; i++){
  	check_addr(esp+ i);
  }

  switch(syscall_num)
  {
    case SYS_HALT:
        halt();
	break;
    case SYS_EXIT:

          printf(" exiting <<<<<<%d>>>>>>\n",thread_current()->tid);
	    exit(*(esp + 1));
	break;
    case SYS_EXEC:
        check_addr(*(esp + 1));
	    f->eax  = exec((char *)*(esp + 1));
	break;
    case SYS_WAIT:
        f->eax =wait(*(esp + 1));
        break;
    case SYS_CREATE:
         check_addr(*(esp + 1));
         f->eax =create((char *)*(esp + 1), *(esp + 2));
         break;
    case SYS_REMOVE:
         check_addr(*(esp + 1));
         f->eax =remove((char *)*(esp + 1));
         break;
    case SYS_OPEN: 
         check_addr(*(esp + 1));
         f->eax =open((char *)*(esp + 1));
         break;
    case SYS_FILESIZE:
         f->eax =filesize(*(esp + 1));
         break;
    case SYS_READ: 
         check_addr(*(esp + 2));
         f->eax =read(*(esp + 1), (void *)*(esp + 2), *(esp + 3));
         break;
    case SYS_WRITE:
         check_addr(*(esp + 2));
         f->eax =write(*(esp + 1), (void *)*(esp + 2), *(esp + 3));
         break;
    case SYS_SEEK: 
         seek(*(esp + 1), *(esp + 2));
         break;
    case SYS_TELL: 
         f->eax =tell(*(esp + 1));
         break;
    case SYS_CLOSE:
         close(*(esp + 1));
         break;

  }
  
  //thread_exit ();
}


void 
halt(void)
{
	shutdown_power_off();
}

void 
exit(int status)
{
	struct  thread * t = thread_current();
	struct list_elem *e;
	for (e = list_begin (&t->parent->children); e != list_end (&t->parent->children);
       e = list_next (e))
      {
        if(t->tid == list_entry (e, struct process, child_elem)->pid){
        struct process *temp = list_entry (e, struct process, child_elem);
        temp->exit_status = status ;
      }
    }
	thread_exit();
}

pid_t 
exec(const char *cmd_line)
{
    pid_t pid;
	if(cmd_line!=NULL){
	     pid =process_execute(cmd_line);
         return pid ; 
	}
	return NULL;
}

int 
wait(pid_t pid)
{
	return process_wait(pid);
}

bool 
create (const char *file, unsigned initial_size)
{
	lock_acquire(&filesys_syscalls_lock);

	if(!is_valid_pointer(file))
	{ 
		lock_release(&filesys_syscalls_lock);
		exit(-1);
	}
	
	bool success = filesys_create (file, initial_size);
	lock_release(&filesys_syscalls_lock);
	return success;
}

bool 
remove(const char *file)
{
	lock_acquire(&filesys_syscalls_lock);

	if(!is_valid_pointer(file))
	{ 
		lock_release(&filesys_syscalls_lock);
		exit(-1);
	}

	bool success = filesys_remove (file);
	lock_release(&filesys_syscalls_lock);
	return success;
}

int 
open(const char *file)
{
	lock_acquire(&filesys_syscalls_lock);

	if(!is_valid_pointer(file))
	{ 
		lock_release(&filesys_syscalls_lock);
		exit(-1);
	}

	struct file *file_ptr = filesys_open (file);

	if(file_ptr == NULL)
	{
		lock_release(&filesys_syscalls_lock);
		return FAILURE;
	}

	file_ptr->fd = thread_current()->fd;
	thread_current()->fd++;
	list_push_back(&thread_current()->file_list, &file_ptr->file_elem);
	lock_release(&filesys_syscalls_lock);
	return file_ptr->fd;
}

int 
filesize(int fd)
{
	lock_acquire(&filesys_syscalls_lock);

	if(fd > 1)
	{
		struct file* opened_file = get_opened_file_with_fd(fd);
		if(opened_file == NULL)
		{
			lock_release(&filesys_syscalls_lock);
			return FAILURE;
		}

		int length = file_length(opened_file);
		lock_release(&filesys_syscalls_lock);
		return length;
	}

	lock_release(&filesys_syscalls_lock);
    return FAILURE;
}

int 
read(int fd, void *buffer, unsigned size)
{
	lock_acquire(&filesys_syscalls_lock);

	// read from the keyboard using input_getc()
	if(fd == STDIN_FILENO)
	{
		int i;
		uint8_t *buffer_ptr = (uint8_t *) buffer;
		for(i = 0; i < size; i++)
		{
			buffer_ptr[i] = input_getc();
		}

		lock_release(&filesys_syscalls_lock);
		return size;
	}

	if(!is_valid_pointer(buffer) || !is_valid_pointer(buffer + size))
	{ 
		lock_release(&filesys_syscalls_lock);
		exit(-1);
	}

	// read from an opened file with the specified fd 
	if(fd > 1)
	{
		struct file* opened_file = get_opened_file_with_fd(fd);

		if(opened_file == NULL)
		{
			lock_release(&filesys_syscalls_lock);
			return FAILURE;
		}

		int readed_bytes = file_read(opened_file, buffer, size);
		lock_release(&filesys_syscalls_lock);
		return readed_bytes;
	}

	lock_release(&filesys_syscalls_lock);
	return FAILURE;
}

int 
write(int fd, const void *buffer, unsigned size)
{
	lock_acquire(&filesys_syscalls_lock);

	// write to the console using putbuf()
	if(fd == STDOUT_FILENO){
		
		putbuf(buffer, size);
		lock_release(&filesys_syscalls_lock);
		return size;
	}	

	if(!is_valid_pointer(buffer) || !is_valid_pointer(buffer + size))
	{ 
		lock_release(&filesys_syscalls_lock);
		exit(-1);
	}

	// write to an opened file with the specified fd 
	if(fd > 1)
	{
		struct file* opened_file = get_opened_file_with_fd(fd);

		if(opened_file == NULL)
		{
			lock_release(&filesys_syscalls_lock);
			return FAILURE;
		}

		int written_bytes = file_write(opened_file, buffer, size);
		lock_release(&filesys_syscalls_lock);
		return written_bytes;
	}

	lock_release(&filesys_syscalls_lock);
	return FAILURE;
}

void 
seek(int fd, unsigned position)
{
	lock_acquire(&filesys_syscalls_lock);
	if(fd > 1)
	{
		
		struct file* opened_file = get_opened_file_with_fd(fd);

		if(opened_file == NULL)
		{
			lock_release(&filesys_syscalls_lock);
			return;
		}

		file_seek(opened_file, position);
	}
	lock_release(&filesys_syscalls_lock);
}

unsigned 
tell(int fd)
{
	lock_acquire(&filesys_syscalls_lock);

	if(fd > 1)
	{
		struct file* opened_file = get_opened_file_with_fd(fd);

		if(opened_file == NULL)
		{
			lock_release(&filesys_syscalls_lock);
			return 0;		
		}

		off_t offset = file_tell(opened_file);
		lock_release(&filesys_syscalls_lock);
		return offset;
	}

	lock_release(&filesys_syscalls_lock);
	return 0;		
}

void 
close (int fd)
{
	// Here, I close only one file with the specified fd 
	// to close all, The work is done in process_exit()
	lock_acquire(&filesys_syscalls_lock);

	if(fd > 1)
	{
		struct thread *cur = thread_current();
		struct list_elem *e;
		for (e = list_begin (&cur->file_list); e != list_end (&cur->file_list); e = list_next (e))
		{
			struct file *file_ptr = list_entry (e, struct file, file_elem);
			if (fd == file_ptr->fd)
			{
				list_remove(&file_ptr->file_elem);
      			file_close(file_ptr);
      			break;
			}
		}
	}

	lock_release(&filesys_syscalls_lock);
}

struct file* 
get_opened_file_with_fd (int fd)
{
	struct thread *cur = thread_current();
	struct list_elem *e;

	for (e = list_begin (&cur->file_list); e != list_end (&cur->file_list); e = list_next (e))
    {
    	struct file *file_ptr = list_entry (e, struct file, file_elem);
    	if (fd == file_ptr->fd)
	    {
	    	return file_ptr;
	    }
    }
    return NULL;
}

void 
remove_all_opened_files(void)
{
  struct list_elem *next;
  struct thread *cur = thread_current();
  struct list_elem *e = list_begin (&cur->file_list);

  while (e != list_end (&cur->file_list))
    {
      next = list_next(e);
      struct file *file_ptr = list_entry (e, struct file, file_elem);
      list_remove(&file_ptr->file_elem);
      file_close(file_ptr);
      e = next;
    }
}
