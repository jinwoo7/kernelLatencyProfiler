#include <linux/module.h> 	/* Needed by all modules */
#include <linux/kernel.h> 	/* KERN_INFO */
#include <linux/init.h> 	/* Init and exit macros */
#include <linux/printk.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <linux/stacktrace.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/hash.h>
#include <linux/proc_fs.h>
#include <asm/time.h>
#include <linux/types.h>
#include "latprof.h"

#define SLOTS_HASH_BITS 16
#define TASK_COMM_LEN 16

static DEFINE_HASHTABLE(jwy_hashtable, SLOTS_HASH_BITS);

/*void hashTableImplementation (int* intlist, int size) {
	struct hashtable_slot *jwy_node, *current_node;
	int i;
	// building hash table
	hash_init(jwy_hashtable);
	for (i = 0; i < size; i++) {
		jwy_node = kmalloc(sizeof(*jwy_node), GFP_KERNEL);
		jwy_node->data = intlist[i];
		INIT_HLIST_NODE(&jwy_node->hash);
		hash_add(jwy_hashtable, &jwy_node->hash, jwy_node->data);
	}
	// iterating hashtable and printing out data
	hash_for_each(jwy_hashtable, i, current_node, hash) {
		printk(KERN_INFO "Hash Table output: %d\n", current_node->data);
	}
	// accessing each bucket and printing the match, free, and destructing the hashtable
	for (i = 0; i < size; i++) { 
		hash_for_each_possible(jwy_hashtable, current_node, hash, intlist[i]) {
			if (current_node->data == intlist[i]) {
				printk(KERN_INFO "Hash Bucket: %d, Value: %d\n", intlist[i], current_node->data);
			}
			hash_del(&current_node->hash);
			kfree(current_node);
		}
	}	
	hash_init(jwy_hashtable);
}*/

/*
#define PROCFS_MAX_SIZE		1024
#define PROCFS_NAME		"lattop"

// This structure hold information about the /proc file
static struct proc_dir_entry *Our_Proc_File;

// The buffer used to store character for this module
static char procfs_buffer[PROCFS_MAX_SIZE];

// The size of the buffer
static unsigned long procfs_buffer_size = 0;

// The function is called then the /proc file is write
int procfile_write(struct file *file, const char *buffer, unsigned long count, void *data) {
	// get buffer size
	procfs_buffer_size = count;
	if (procfs_buffer_size > PROCFS_MAX_SIZE) {
		procfs_buffer_size = PROCFS_MAX_SIZE;
	}

	// write data to the buffer
	if (copy_from_user(procfs_buffer, buffer, procfs_buffer_size)) {
		return -EFAULT;
	}

	return procfs_buffer_size;
}
*/

static struct kprobe sleepProbe = {
	.symbol_name = "activate_task",
};

static struct kprobe activeProbe = {
	.symbol_name = "deactivate_task",
};

static int sleepProbe_handler(struct kprobe *p, struct pt_regs *regs) {
	int i = 0, writeNum = 0;
	int stringSize = 200;

	struct task_struct *my_task_struct = (struct task_struct*)(regs->si);	
	pid_t my_pid = my_task_struct->pid;

	unsigned long * my_entries = kmalloc(MAX_STACK_TRACE * sizeof(*my_entries), GFP_ATOMIC);
	if (my_entries == NULL) {
		return -1;
	}
	struct stack_trace *my_trace = kmalloc(sizeof(*my_trace), GFP_ATOMIC);
	if (my_trace == NULL) {
		return -1;
	}
	char *traceStr = kmalloc(stringSize * sizeof(*traceStr), GFP_ATOMIC);
	if (traceStr == NULL) {
		return -1;
	}

	my_trace->max_entries = MAX_STACK_TRACE;
	my_trace->nr_entries = 0;
	my_trace->entries = my_entries;

	save_stack_trace_tsk(my_task_struct, my_trace);
	snprint_stack_trace(traceStr, stringSize, my_trace, 0);
	printk(KERN_INFO "%s\n", traceStr);	
	
	//struct task_struct *my_task_struct = ((struct task_struct*)(regs->si));
	
	char *my_comm = kmalloc(TASK_COMM_LEN * sizeof(char), GFP_ATOMIC);
	memcpy((void *)my_comm, (void*)((struct task_struct*)(regs->si))->comm, TASK_COMM_LEN);
	//my_comm = ((struct task_struct*)(regs->si))->comm;
	//((struct task_struct*)(regs->si))->comm;
	//save_stack_trace_tsk(my_task_struct, trace);
	/*
	struct task_latency_info *latency_info;
	if (latency_info = kmalloc(sizeof(*latency_info), GFP_KERNEL) == NULL) {
		printk("kmalloc failed\n");
	}
	*/
			
	printk(KERN_INFO "------------------- sleep ---------------------\n");
	printk(KERN_INFO "PID = %u, comm = %s\n", 
			my_pid,
			//((struct task_struct*)(regs->si))->comm);
			my_comm);
	
	kfree(my_comm);	
	kfree(my_entries);
	kfree(my_trace);
	kfree(traceStr);
	return 0;
}

static int activeProbe_handler(struct kprobe *p, struct pt_regs *regs) {
	printk(KERN_INFO "------------------- active ---------------------\n");
	return 0;
}

/* kprobe handler for sleeping tasks */
static int sleep_handler 		(struct kprobe *p, struct pt_regs *pr) {
	return 1;
}

/* kprobe handler for waking up tasks */
static int wake_up_handler 		(struct kprobe *p, struct pt_regs *pr) {
	return 1;
}

static void save_task_stack_trace 	(struct task_struct *ts, struct task_stack_trace *tst, int st) {
}
static void print_task_stack_trace 	(struct seq_file *sf, struct task_stack_trace *tst, const int st) {
}
static void print_task_latency_info	(struct seq_file *sf, struct task_latency_info *tli) {
}

/* start the cpu timer */
static void start_task_timer		(struct task_struct *ts) {
}
/* stops the cpu timer */
static void stop_task_timer		(struct task_struct *ts, u64 time) {
}
/* deinitialize the timer */
static void deinit_task_time		(void) {
}

/* Updates the task struct with new ellapsed task sleep cycle */
static void update_task_latency_info	(struct task_struct *tsk, u64 elapsed_tsc) {
}

static int latprof_stat_open		(struct inode *inode, struct file *file) {
}



static int __init latprof_init(void) {
	int sret, aret;
	
	/*
	Our_Proc_File = create_proc_entry(PROCFS_NAME, 0644, NULL);

	if (Our_Proc_File == NULL) {
		remove_proc_entry(PROCFS_NAME, &proc_root);
		prink(KERN_ALERT "Error: Could not initialize /proc/%s\n", PROCFS_NAME);
		return -ENOMEM;
	}
	Our_Proc_File->read_proc 	= profile_read;
	Our_Proc_File->owner		= THIS_MODULE;
	Our_Proc_File->mode		= S_IFREG | S_IRUGO;
	Our_Proc_File->uid		= 0;
	Our_Proc_File->gid		= 0;
	Our_Proc_File->size 		= 37;
	*/

	sleepProbe.pre_handler = sleepProbe_handler;
	activeProbe.pre_handler = activeProbe_handler;
	sret = register_kprobe(&sleepProbe);
	aret = register_kprobe(&activeProbe);

	if(sret < 0) {
		printk("AYYYYYYYYYYOOOOOOOOOOOO\n", sret);
		return sret;
	}

	if(aret < 0) {
		printk("EEEEEEEEEEEEEEEEEEEEEEE\n", aret);
		return aret;
	}
	
	printk(KERN_INFO "###################################################\n");
	printk(KERN_INFO "############## Latprof starting ... ###############\n");
	printk(KERN_INFO "###################################################\n");
	printk(KERN_INFO "current clock cycle %u\n", rdtsc());
	return 0; /* return 0 on success, something else on error */
}

static void __exit latprof_exit(void) {
	unregister_kprobe(&sleepProbe);
	unregister_kprobe(&activeProbe);
	printk(KERN_INFO "###################################################\n");
	printk(KERN_INFO "############## Latprof exiting ... ################\n");
	printk(KERN_INFO "###################################################\n");
}

module_init(latprof_init); 	/* latprof_init() will be called at loading the module */
module_exit(latprof_exit); 	/* latprof_exit() will be called at unloading the module */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jinwoo Yom <jinwoo7@vt.edu>");
MODULE_DESCRIPTION("Sample kernel module");
