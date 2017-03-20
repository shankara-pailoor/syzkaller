#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)
#define COVER_SIZE (16 << 20)
#define TRACE_OPTIONS (PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXIT | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK)

int debug;

struct pid_metadata {
	int id; //we might see the same pid twice
	int just_forked;
	int enter_stop;
	int position;
	int is_main_tracee;
	unsigned long mmap_area; //pointer to coverage map
};

struct pid_metadata seen_pids[65000] = {0};

int do_wait(pid_t pid, const char *name) {
	int status;

	if (waitpid(pid, &status, __WALL) == -1) {
		perror("wait");
		return -1;
	}
	if (WIFSTOPPED(status)) {
		if (WSTOPSIG(status) == (SIGTRAP | 0x80) || WSTOPSIG(status) == SIGTRAP) {
      			return 0;
    		}
    		printf("%s unexpectedly got status %s\n", name, strsignal(status));
		return -1;
	} else if (WIFEXITED(status)) {
  		printf("%s got unexpected status %d\n", name, status);
	}
	return -1;
}

int singlestep(pid_t pid) {
	if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)) {
		perror("PTRACE_SINGLESTEP");
		return -1;
	}
	return do_wait(pid, "PTRACE_SINGLESTEP");
}

int poke_text(pid_t pid, void *where, void *new_text, void *old_text, size_t len) {
	size_t copied;
	long poke_data, peek_data;
	if (len % sizeof(void *) != 0) {
		printf("invalid len, not a multiple of %zd\n", sizeof(void *));
		return -1;
	}

	for (copied = 0; copied < len; copied += sizeof(poke_data)) {
		memmove(&poke_data, new_text + copied, sizeof(poke_data));
		if (old_text != NULL) {
			errno = 0;
			peek_data = ptrace(PTRACE_PEEKTEXT, pid, where + copied, NULL);
			if (peek_data == -1 && errno) {
				perror("PTRACE_PEEKTEXT");
				return -1;
			}
			memmove(old_text + copied, &peek_data, sizeof(peek_data));
		}
		if (ptrace(PTRACE_POKETEXT, pid, where + copied, (void *)poke_data) < 0) {
			perror("PTRACE_POKETEXT");
			return -1;
		}
	}
	return 0;
}

int cover_buf_flush(pid_t pid, FILE* fp) {
	unsigned long cover_addr;
	unsigned long ip;
	int i, n;

	i = seen_pids[pid].position;
	cover_addr = seen_pids[pid].mmap_area;

	if (seen_pids[pid].is_main_tracee) {
		printf("is main tracee\n");
		n = __atomic_load_n((unsigned long *)cover_addr, __ATOMIC_RELAXED);
		printf("n: %d\n", n);
	} else if ((n = ptrace(PTRACE_PEEKDATA, pid, cover_addr, NULL)) < 0) {
		perror("PTRACE_PEEKDATA");
		return -1;
	}

	while(i < n) {
		if (!seen_pids[pid].is_main_tracee)
			ip = ptrace(PTRACE_PEEKDATA, pid, cover_addr + (i+1)*sizeof(unsigned long), NULL);
		else
			ip = ((unsigned long *)cover_addr)[i+1];
		fprintf(fp, "0x%lx\n", ip);
		i++;
	}
	seen_pids[pid].position = n;
	return 0;
}

/**
* After a fork, clone, or vfork we insert instructions
* to setup kcov before the first system call. The below is currently
* an x86_64 specific implementation.
*/
unsigned long setup_kcov(int fd, pid_t pid) {
	unsigned long cover_buffer;
	unsigned long file_path;
	struct user_regs_struct new_regs, old_regs;
	uint8_t new_instruction[8];
	uint8_t old_instruction[8];

	char path[32] = "/sys/kernel/debug/kcov\0";
	int i;
  
	if (ptrace(PTRACE_GETREGS, pid, NULL, &old_regs)) {
    		perror("PTRACE_GETREGS");
   		ptrace(PTRACE_DETACH, pid, NULL, NULL);
    		return -1;
  	}

	new_instruction[0] = 0x0f; //syscall
	new_instruction[1] = 0x05; //syscall
	new_instruction[2] = 0xff; //jmp
	new_instruction[3] = 0xe0; //rax

	memmove(&new_regs, &old_regs, sizeof(new_regs));

	//Mmap memory in tracee for kcov file path
	new_regs.rip = old_regs.rip;
	new_regs.orig_rax = 9; //mmap 
	new_regs.rax = 9; //mmap
	new_regs.rdi = 0; //NULL
	new_regs.rsi = PAGE_SIZE; //Length
	new_regs.rdx = PROT_READ | PROT_WRITE; //Protection
	new_regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS; //Flags
	new_regs.r8 = -1; //Fd
	new_regs.r9 = 0; //Offset

	//Replace the old instruction with new one and save old instruction
	if (poke_text(pid, (void *) old_regs.rip, new_instruction, old_instruction, sizeof(new_instruction))) {
    		goto fail;
  	}

  	// set the new registers with our syscall arguments
  	if (ptrace(PTRACE_SETREGS, pid, NULL, &new_regs)) {
    		perror("PTRACE_SETREGS");
    		goto fail;
  	}

	if (singlestep(pid))
		goto fail;

	if (ptrace(PTRACE_GETREGS, pid, NULL, &new_regs)) {
    		perror("PTRACE_GETREGS");
    		return -1;
  	}	

	//address of mmap for file path
	file_path = (unsigned long)new_regs.rax;

	if ((void *)new_regs.rax == MAP_FAILED) {
		printf("failed to mmap\n");
		goto fail;
	}

	//write kcov path to tracee's address space
	if (poke_text(pid, (void *) file_path, path, NULL, sizeof(path))) {
		printf("FAILED COPY\n");
	}

	//Open Kcov
	if (debug)
		printf("before open\n");
	new_regs.rip = old_regs.rip;
	new_regs.orig_rax = 2;
	new_regs.rax = 2;
	new_regs.rdi = file_path;
	new_regs.rsi = O_CREAT|O_RDWR;
	new_regs.rdx = 0;
	
	if (poke_text(pid, (void *) old_regs.rip, new_instruction, NULL, sizeof(new_instruction))) {
    		goto fail;
  	}

  	// set the new registers with our syscall arguments
  	if (ptrace(PTRACE_SETREGS, pid, NULL, &new_regs)) {
    		perror("PTRACE_SETREGS");
    		goto fail;
  	}

	if (singlestep(pid))
		goto fail;

	if (ptrace(PTRACE_GETREGS, pid, NULL, &new_regs)) {
    		perror("PTRACE_GETREGS");
    		return -1;
  	}

	fd = new_regs.rax;
	if (debug)
		printf("file descriptor: %d\n", fd);

	//Initialize trace
	new_regs.rip = old_regs.rip;
	new_regs.orig_rax = 16;
	new_regs.rax = 16;
	new_regs.rdi = fd;
	new_regs.rsi = KCOV_INIT_TRACE;
	new_regs.rdx = COVER_SIZE;

	if (poke_text(pid, (void *) old_regs.rip, new_instruction, NULL, sizeof(new_instruction))) {
    		goto fail;
  	}

  	// set the new registers with our syscall arguments
  	if (ptrace(PTRACE_SETREGS, pid, NULL, &new_regs)) {
    		perror("PTRACE_SETREGS");
    		goto fail;
  	}

	if (singlestep(pid))
		goto fail;


	if (ptrace(PTRACE_GETREGS, pid, NULL, &new_regs)) {
                perror("PTRACE_GETREGS");
                return -1;
        }

	printf("kcov init: %d\n", new_regs.rax);

	//Set up cover map in tracee
	new_regs.rip = old_regs.rip;
	new_regs.orig_rax = 9; //MMAP
	new_regs.rax = 9; //Default rax
	new_regs.rdi = 0; //Pointer to the base
	new_regs.rsi = COVER_SIZE*sizeof(unsigned long); //Length
	new_regs.rdx = PROT_READ | PROT_WRITE; //Mode
	new_regs.r10 = MAP_PRIVATE; //We want mmap at particular offset
	new_regs.r8 =  fd; //kcov filedescriptor
	new_regs.r9 = 0; //

	if (poke_text(pid, (void *) old_regs.rip, new_instruction, NULL, sizeof(new_instruction))) {
    		goto fail;
	}

  	// set the new registers with our syscall arguments
  	if (ptrace(PTRACE_SETREGS, pid, NULL, &new_regs)) {
    		perror("PTRACE_SETREGS");
    		goto fail;
  	}

  	// invoke mmap(2)
  	if (singlestep(pid)) {
   		goto fail;
 	}

	if (ptrace(PTRACE_GETREGS, pid, NULL, &new_regs)) {
    		perror("PTRACE_GETREGS");
    		return -1;
  	}

	// this is the address of the memory we allocated
	cover_buffer = (unsigned long)new_regs.rax;
	if ((void *)new_regs.rax == MAP_FAILED) {
		printf("failed to mmap\n");
		goto fail;
	}
	printf("allocated memory at  %p\n", (void *)new_regs.rax);

	//Enable coverage
	new_regs.rip = old_regs.rip;
	new_regs.orig_rax = 16;
	new_regs.rax = 16;
	new_regs.rdi = fd;
	new_regs.rsi = KCOV_ENABLE;
	new_regs.rdx = 0;

	if (poke_text(pid, (void *) old_regs.rip, new_instruction, NULL, sizeof(new_instruction))) {
    		goto fail;
  	}

  	// set the new registers with our syscall arguments
  	if (ptrace(PTRACE_SETREGS, pid, NULL, &new_regs)) {
    		perror("PTRACE_SETREGS");
    		goto fail;
  	}

	if (singlestep(pid))
		goto fail;


	if (ptrace(PTRACE_GETREGS, pid, NULL, &new_regs)) {
		perror("PTRACE_GETREGS");
		goto fail;
        }
 
	//Restore old instruction
	if (poke_text(pid, (void *) old_regs.rip, old_instruction, NULL, sizeof(old_instruction))) {
		goto fail;
	}

	//Restore old registers
	if (ptrace(PTRACE_SETREGS, pid, NULL, &old_regs)) {
    		perror("PTRACE_SETREGS");
    		goto fail;
  	}

	return (unsigned long) cover_buffer;

fail:
	exit(1);
}


int handle_status(int fd, pid_t child, int status, FILE* fp, unsigned long * cover) {
	int ret, syscall, i;
	unsigned long n;
	long new_fork;

	if (debug)
		printf("handling status\n");
	if (WIFEXITED(status)) {
		printf("exited1\n");
		return 1;
	}
	switch ((status >> 8)) {
	case (SIGTRAP | PTRACE_EVENT_FORK << 8):
		{
			if (debug)
				printf("forked event\n");
			if (ptrace(PTRACE_GETEVENTMSG, child, 0, &new_fork) < 0) {
				printf("can't get message\n");
				if (errno == -ESRCH)
					return -1;
			}
			seen_pids[new_fork].id += 1;
			seen_pids[new_fork].enter_stop = -1;
			seen_pids[new_fork].just_forked = 1;
			seen_pids[new_fork].position = 0;
			seen_pids[new_fork].is_main_tracee = 0;
			ret = 0;
			goto out;
		}
	case (SIGTRAP | (PTRACE_EVENT_EXEC << 8)):
		ret = -1; goto out;
	case (SIGTRAP | (PTRACE_EVENT_VFORK << 8)):
		{
			if (debug)
				printf("forked event\n");
			if (ptrace(PTRACE_GETEVENTMSG, child, 0, &new_fork) < 0) {
				if (errno == -ESRCH)
					return -1;
			}
			seen_pids[new_fork].id += 1;
			seen_pids[new_fork].enter_stop = -1;
			seen_pids[new_fork].is_main_tracee = 0;
			ret = 0; goto out;
		}
	default:
		if ((status == SIGTRAP | 0x80)) {
			if (debug)
				printf("received syscall");
			if (seen_pids[child].just_forked == 1) {
				seen_pids[child].mmap_area = setup_kcov(fd, child);
				seen_pids[child].just_forked = 0;
				ret = 0; goto out;
			}
			syscall = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX);
           		n = __atomic_load_n(cover, __ATOMIC_RELAXED);
			if (seen_pids[child].enter_stop == 1 || seen_pids[child].enter_stop == -1) {
				int pos = ptrace(PTRACE_PEEKDATA, child, seen_pids[child].mmap_area, NULL);
				printf("pos: %d\n", pos);
				seen_pids[child].position = pos;
				seen_pids[child].enter_stop = 0;
			} else  {
				fprintf(fp, "pid: %d, start syscall(%d)\n", child, syscall);
				cover_buf_flush(child, fp);
				fprintf(fp, "pid: %d, end syscall(%d)\n", child, syscall);
				seen_pids[child].enter_stop = 1;
			}
			__atomic_store_n(cover, 0, __ATOMIC_RELAXED);
			ret = 0; goto out;
		}
		break;
	}

out:
	if (ptrace(PTRACE_SYSCALL, child, 0, 0))
		printf("failed to resume\n");
	return ret;
}

void initialize_tracee(int fd, unsigned long *cover) {
	ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	raise(SIGSTOP); //wait for tracer to hook on us
	if (ioctl(fd, KCOV_ENABLE, 0))
		perror("ioctl"), exit(1);
	__atomic_store_n(cover, 0, __ATOMIC_RELAXED);
	return;
}

void initialize_tracer(pid_t pid, unsigned long cover) {
	int status;
	if (waitpid(pid, &status, 0) < 0)
		printf("waitpid failed\n");
	if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
		kill(pid, SIGKILL);
		printf("tracer: unexpected wait status: %x", status);
	}
        if (ptrace(PTRACE_SETOPTIONS, pid, NULL, TRACE_OPTIONS) < 0)
		printf("failed ptrace: %d\n", errno);
	seen_pids[pid].mmap_area = cover;
	seen_pids[pid].position = 0;
	seen_pids[pid].enter_stop = 1;
	seen_pids[pid].just_forked = -1;
	seen_pids[pid].is_main_tracee = 1;
	ptrace(PTRACE_SYSCALL, pid, 0, 0);
	return;
}

int main(int argc, char **argv, char **envp) {
	int fd, fd1, pid, status;
	unsigned long *cover, *main_tracee_cover, n, i;
	FILE* fp;
	
	/*
	*TODO: Add an options parser.
	* -f indicates follow fork
	* -s indicates to log only syscall start and finish
	* -d is debug
	*/
    
    	if (argc == 1)
    		fprintf(stderr, "usage: kcovtrace program [-o outputfile] [args...]\n"), exit(1);
    	if (strncmp(argv[1],"-o", 3) == 0) {
        	if (argc < 4)
            		fprintf(stderr, "usage: kcovtrace program [-o outputfile] [args...]\n"), exit(1);
        	fd1 = open(argv[2], O_CREAT|O_RDWR);
        	if (fd1 == -1)
   	        	perror("open"), exit(1);
   		fp = fdopen(fd1, "w");
   	 } else {
   		fp = stdout;
    	}
    	fd = open("/sys/kernel/debug/kcov", O_RDWR);
    	if (fd == -1)
       		perror("open"), exit(1);
	if (ioctl(fd, KCOV_INIT_TRACE, COVER_SIZE))
     		perror("ioctl"), exit(1);

	main_tracee_cover = (unsigned long *)mmap(NULL, COVER_SIZE*sizeof(unsigned long),
				PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if ((void *)main_tracee_cover == MAP_FAILED)
		perror("mmap"), exit(1);
	if (debug)
		printf("MAIN TRACEE COVER: %lu\n", (unsigned long)main_tracee_cover);
	pid = fork();
    	if (pid == 0) {
       		initialize_tracee(fd, main_tracee_cover);
    		if (fd1 >= 0)
    	   		 execve(argv[3], argv + 3, envp);
    		else
    	    		execve(argv[1], argv + 1, envp);
    		perror("execve");
    		exit(1);
    	} else {
		int status;
		pid_t waiting_pid;
		
		initialize_tracer(pid, (unsigned long)main_tracee_cover);
		while(waiting_pid = waitpid(-1, &status, __WALL)) {
			if (waiting_pid == -1 && errno == ECHILD)
				break;
			handle_status(fd, waiting_pid, status, fp, main_tracee_cover);
		}
   	}
	return 0;
}
