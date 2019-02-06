#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <asm/errno.h>
//#include <asm/current.h>
unsigned long **sys_call_table;


asmlinkage long (*ref_sys_cs3013_syscall1)(void);
asmlinkage long (*ref_sys_cs3013_syscall2)(void);

struct ancestry 
{
	pid_t ancestors[10];
	pid_t siblings[100];
	pid_t children[100];
};



asmlinkage long new_sys_cs3013_syscall1(void) 
{
	printk(KERN_INFO "\"'Hello world?!' More like 'Goodbye, world!' EXTERMINATE!\" -- Dalek");
	return 0;
}

asmlinkage long new_sys_cs3013_syscall2(unsigned short *target_pid, struct ancestry *response)
{

	int childrenInc = 0;
	int siblingsInc = 0;
	int ancestorsInc = 0;
	pid_t zero = 0;
	// Allocate space in the kernel space for the target pid
	unsigned short theTarget;

	struct task_struct *ourTask;

	struct task_struct *pos;
	if(copy_from_user(&theTarget, target_pid, sizeof(unsigned short))){
		return EFAULT;
	}

	// Get the task struct at our tast	
	ourTask = pid_task((find_get_pid(theTarget)), PIDTYPE_PID);

	printk(KERN_INFO "We found the task!\n");	

	// Loop through the siblings of one of our children
	list_for_each_entry( pos ,&ourTask->children, sibling){
		// As long as we aren't maxing out the array, go	
		if(childrenInc < 100){
			// If we receive some kind of error, fault	
			if(copy_to_user(&response->children[childrenInc], &pos->pid, sizeof(pid_t))){
		
				return EFAULT;
			}
			// Print and increment	
			printk(KERN_INFO "Child pid: %hu\n", pos->pid);
			childrenInc++;
		}
	}

	// If we have less than the max number of items in the array, pad with zeroes
	if(childrenInc < 100){
		copy_to_user(&response->children[childrenInc], &zero, sizeof(pid_t));
	}

	//Loop through the siblings of our node
	list_for_each_entry(pos, &ourTask->sibling, sibling){
		// As long as we aren't maxing out the array, go.
		if(siblingsInc < 100){
			if(pos->pid != 0){
				
				// If we receive some kind of error, fault
				if(copy_to_user(&response->siblings[siblingsInc], &pos->pid, sizeof(pid_t))){
					return EFAULT;
				}
				// Print and increment
				printk(KERN_INFO "Sibling pid: %hu\n", pos->pid);
			
				siblingsInc++;
			}
		}
	}
	
	// If we have less than the max number of items in the array, pad with zeroes
	if(siblingsInc < 100){
		copy_to_user(&response->siblings[siblingsInc], &zero, sizeof(pid_t));
	}

	// Go up the process ancestry
	ourTask = ourTask->real_parent;
	while(ourTask->pid != 0 ){
		if(ancestorsInc < 10){
			// If we reach an error, fault	
			if(copy_to_user(&response->ancestors[ancestorsInc], &ourTask->pid, sizeof(pid_t))){
				return EFAULT;
			}
			// Print the ancestor's pid to the kernel and increment
			printk(KERN_INFO "Ancestor pid: %hu\n", ourTask->pid);
			ancestorsInc++;	
			ourTask = ourTask->real_parent;
		}
	}	
	
	// If we have less than the max number of items in the array, pad with zeros
	if(ancestorsInc < 10){
		copy_to_user(&response->ancestors[ancestorsInc], &zero, sizeof(pid_t));
	}

	return 0;
}

/*
    Locates the sys call table and stores it in a pointer
*/
static unsigned long **find_sys_call_table(void)
{
    unsigned long int offset = PAGE_OFFSET;
    unsigned long **sct;

    while (offset < ULLONG_MAX)
    {
        sct = (unsigned long **)offset;

        if (sct[__NR_close] == (unsigned long *) sys_close)
        {
            printk(KERN_INFO "Interceptor: Found syscall table at address: 0x%02lX",
                    (unsigned long) sct);
            return sct;
        }

        offset += sizeof(void *);
    }

    return NULL;
}


static void disable_page_protection(void) 
{
	/*
	   Control Register 0 (cr0) governs how the CPU operates.

	   Bit #16, if set, prevents the CPU from writing to memory marked as
	   read only. Well, our system call table meets that description.
	   But, we can simply turn off this bit in cr0 to allow us to make
	   changes. We read in the current value of the register (32 or 64
	   bits wide), and AND that with a value where all bits are 0 except
	   the 16th bit (using a negation operation), causing the write_cr0
	   value to have the 16th bit cleared (with all other bits staying
	   the same. We will thus be able to write to the protected memory.

	   It's good to be the kernel!
	 */
	write_cr0 (read_cr0 () & (~ 0x10000));
}

static void enable_page_protection(void) 
{
	/*
	   See the above description for cr0. Here, we use an OR to set the 
	   16th bit to re-enable write protection on the CPU.
	 */
	write_cr0 (read_cr0 () | 0x10000);
}

static int __init interceptor_start(void) 
{
	/* Find the system call table */
	if(!(sys_call_table = find_sys_call_table())) 
{
		/* Well, that didn't work. 
		   Cancel the module loading step. */
		return -1;
	}

	/* Store a copy of all the existing functions */
	ref_sys_cs3013_syscall1 = (void *)sys_call_table[__NR_cs3013_syscall1];
	ref_sys_cs3013_syscall2 = (void *)sys_call_table[__NR_cs3013_syscall2];

	/* Replace the existing system calls */
	disable_page_protection();

	sys_call_table[__NR_cs3013_syscall1] = (unsigned long *)new_sys_cs3013_syscall1;
	sys_call_table[__NR_cs3013_syscall2] = (unsigned long *)new_sys_cs3013_syscall2;

	enable_page_protection();

	/* And indicate the load was successful */
	printk(KERN_INFO "Loaded interceptor!");

	return 0;
}

static void __exit interceptor_end(void) 
{
	/* If we don't know what the syscall table is, don't bother. */
	if(!sys_call_table)
		return;

	/* Revert all system calls to what they were before we began. */
	disable_page_protection();

	sys_call_table[__NR_cs3013_syscall1] = (unsigned long *)ref_sys_cs3013_syscall1;
	sys_call_table[__NR_cs3013_syscall2] = (unsigned long *)ref_sys_cs3013_syscall2;

	enable_page_protection();

	printk(KERN_INFO "Unloaded interceptor!");
}

MODULE_LICENSE("GPL");
module_init(interceptor_start);
module_exit(interceptor_end);

