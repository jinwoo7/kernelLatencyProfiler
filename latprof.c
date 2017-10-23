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
#define STRING_SIZE 1000

static DEFINE_HASHTABLE(lf_hashtable, SLOTS_HASH_BITS);

static void tl_ht_insert(struct task_latency_info *node) {
	INIT_HLIST_NODE(&node->stack_node);
	hash_add(lf_hashtable, &node->stack_node, node->hash_key);
}

static struct task_latency_info * tl_ht_get(u32 hash_key) {
	//struct task_latency_info *temp = kmalloc(sizeof(*temp), GFP_ATOMIC);
	struct task_latency_info *temp;
	hash_for_each_possible(lf_hashtable, temp, stack_node, hash_key) {
		if (hash_key == temp->hash_key) {
			//printk(KERN_INFO "==================================> pid:%u, comm:%s\n", temp->pid, temp->comm);
			
			return temp;
		}
	}
	return NULL;
}

static void tl_ht_delete(struct task_latency_info *node) {	
	hash_del(&node->stack_node);
	
	kfree(node->trace->entries);
	kfree(node->trace);
	kfree(node);
}

static char * getStackString(struct task_struct *task) {
	int stringSize = 200;
	struct stack_trace *temp_trace = kmalloc(sizeof(*temp_trace), GFP_ATOMIC);
	if (temp_trace == NULL) {
		return -1;
	}
	
	temp_trace->entries = kmalloc(MAX_STACK_TRACE * sizeof(*temp_trace->entries), GFP_ATOMIC);
	if (temp_trace->entries == NULL) {
		return -1;
	}

	temp_trace->max_entries = MAX_STACK_TRACE;
	temp_trace->nr_entries = 0;
	save_stack_trace_tsk(task, temp_trace);
	
	char *traceStr = kmalloc(stringSize * sizeof(*traceStr), GFP_ATOMIC);
	if (traceStr == NULL) {
		return -1;
	}
	
	snprint_stack_trace(traceStr, stringSize, temp_trace, 0);	
	kfree(temp_trace->entries);
	kfree(temp_trace);

	return traceStr;
}

static u32 get_callstack_jhash(struct task_struct *task) {
	char *stackString = getStackString(task);
	u32 hash_entries = jhash(stackString, sizeof(*stackString), 0);
	kfree(stackString);
	return jhash_2words(task->pid, hash_entries, 0);
}

static void print_task_latency_info	(struct seq_file *sf, struct task_latency_info *node) {
	// printing
	int stringSize = 200;
	char *traceStr = kmalloc(stringSize * sizeof(*traceStr), GFP_ATOMIC);
	if (traceStr == NULL) {
		return -1;
	}
	
	snprint_stack_trace(traceStr, stringSize, node->trace, 0);

	latprof_info("------------------- active ---------------------\nPID = %u, COMM = %s, cycles = %u, hash = %u\n%s\n", 
		node->pid, node->comm, node->hash_key, rdtsc(), traceStr);

	kfree(traceStr);
	return 0;
}

static struct kprobe sleepProbe = {
	.symbol_name = "activate_task",
};

static struct kprobe activeProbe = {
	.symbol_name = "deactivate_task",
};

/* kprobe handler for sleeping tasks */
static int sleep_handler 		(struct kprobe *p, struct pt_regs *pr) {
	int i = 0;
	int exist = 0;h
	struct task_struct *my_task_struct = (struct task_struct*)(pr->si);
	u32 key = get_callstack_jhash(my_task_struct);
	// checking to see if the node already exists
		
	
	struct task_latency_info *currTask_info = kmalloc(sizeof(*currTask_info), GFP_ATOMIC);
	if (currTask_info == NULL) {
		return -1;
	} 

	// PID
	currTask_info->pid = my_task_struct->pid;

	// Comm	
	memcpy((void *)currTask_info->comm, (void*)my_task_struct->comm, TASK_COMM_LEN);
	
	// Stack trace
	currTask_info->trace = kmalloc(sizeof(*currTask_info->trace), GFP_ATOMIC);
	if (currTask_info->trace == NULL) {
		return -1;
	}

	currTask_info->trace->entries = kmalloc(MAX_STACK_TRACE * sizeof(*currTask_info->trace->entries), GFP_ATOMIC);
	if (currTask_info->trace->entries == NULL) {
		return -1;
	}

	currTask_info->trace->max_entries = MAX_STACK_TRACE;
	currTask_info->trace->nr_entries = 0;
	save_stack_trace_tsk(my_task_struct, currTask_info->trace); 
	
	// jhash
	currTask_info->hash_key = get_callstack_jhash(my_task_struct);

	// printing
	char *traceStr = kmalloc(STRING_SIZE * sizeof(*traceStr), GFP_ATOMIC);
	if (traceStr == NULL) {
		return -1;
	}
	
	snprint_stack_trace(traceStr, STRING_SIZE, currTask_info->trace, 0);

	latprof_info("------------------- sleep ---------------------\nPID = %u, COMM = %s, cycles = %u, hash = %u\n%s\n", 
		currTask_info->pid, currTask_info->comm, currTask_info->hash_key, rdtsc(), traceStr);

	kfree(traceStr);

	tl_ht_insert(currTask_info);
	return 0;
}


/* kprobe handler for waking up tasks */
static int wake_up_handler 		(struct kprobe *p, struct pt_regs *pr) {

	struct task_struct *my_task_struct = (struct task_struct*)(pr->si);
	u32 key = get_callstack_jhash(my_task_struct);
	struct task_latency_info *node;
	hash_for_each_possible(lf_hashtable, node, stack_node, key) {
		if (key == node->hash_key) {
			// Stack trace
			struct stack_trace *trace = kmalloc(sizeof(*trace), GFP_ATOMIC);
			if (trace == NULL) { return -1; }

			trace->entries = kmalloc(MAX_STACK_TRACE * sizeof(*trace->entries), GFP_ATOMIC);
			if (trace->entries == NULL) { return -1; }

			trace->max_entries = MAX_STACK_TRACE;
			trace->nr_entries = 0;
			save_stack_trace_tsk(my_task_struct, trace);
			// printing
			char *traceStr = kmalloc(STRING_SIZE * sizeof(*traceStr), GFP_ATOMIC);
			if (traceStr == NULL) {
				return -1;
			}
			snprint_stack_trace(traceStr, STRING_SIZE, trace, 0);

			latprof_info("---------------- active ------------------\nPID = %u, COMM = %s, cycles = %u\n%s\n", 
				node->pid, node->comm, rdtsc(), traceStr);

			hash_del(&node->stack_node);
			
			kfree(trace->entries);
			kfree(trace);
			kfree(traceStr);
			
			kfree(node->trace->entries);
			kfree(node->trace);
			kfree(node);
			return 0;
		}
	}
	
	latprof_info("AHHHHHHHHHHHHHHHH WHYYYYYYYYYYYYYYYYYYYYYYY\n");
	return 0;
}
/*
static void save_task_stack_trace 	(struct task_struct *ts, struct task_stack_trace *tst, int st) {
}
*/
/*
static void print_task_stack_trace 	(struct seq_file *sf, struct task_stack_trace *tst, const int st) {
}
*/


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
	hash_init(lf_hashtable);
	sleepProbe.pre_handler = sleep_handler;
	activeProbe.pre_handler = wake_up_handler;
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
	
	latprof_info("###################################################\n");
	latprof_info("############## Latprof starting ... ###############\n");
	latprof_info("###################################################\n");
	latprof_info("current clock cycle %u\n", rdtsc());
	return 0; /* return 0 on success, something else on error */
}

static void __exit latprof_exit(void) {
	int i = 0;
	struct task_latency_info *node;
	unregister_kprobe(&sleepProbe);
	unregister_kprobe(&activeProbe);
	// deacllocate hashtable
	hash_for_each(lf_hashtable, i, node, stack_node) {
		latprof_info("Deleting PID:%u, COMM:%s\n", node->pid, node->comm);
		kfree(node->trace->entries);
		kfree(node->trace);
		hash_del(&node->stack_node);
		kfree(node);
	}
	latprof_info("###################################################\n");
	latprof_info("############## Latprof exiting ... ################\n");
	latprof_info("###################################################\n");
}

module_init(latprof_init); 	/* latprof_init() will be called at loading the module */
module_exit(latprof_exit); 	/* latprof_exit() will be called at unloading the module */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jinwoo Yom <jinwoo7@vt.edu>");
MODULE_DESCRIPTION("Sample kernel module");
