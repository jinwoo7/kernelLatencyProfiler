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
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <asm/time.h>
#include <linux/types.h>
#include "latprof.h"

#define SLOTS_HASH_BITS 16
#define TASK_COMM_LEN 16
#define STRING_SIZE 1000

//DEFINE_SPINLOCK(ht_lock);
//DEFINE_SPINLOCK(rb_lock);

static struct rblack_root_node *rblack_root;

static DEFINE_HASHTABLE(lf_hashtable, SLOTS_HASH_BITS);

static struct timespec *startTime, *currTime;

static struct proc_dir_entry* latprof_file;

static char *traceStr; 

static int latprof_show(struct seq_file *m, void *v) {
	seq_printf(m, "curr cycle: %llu, printing trace: \n%s\n", rdtsc(), traceStr);
	return 0;
}

static void tl_ht_insert(struct task_latency_info *node) {
	INIT_HLIST_NODE(&node->stack_node);
	hash_add(lf_hashtable, &node->stack_node, node->hash_key);
}

static char * getStackString(struct task_struct *task) {
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
	
	char *printStr = kmalloc(STRING_SIZE * sizeof(*printStr), GFP_ATOMIC);
	if (printStr == NULL) {
		return -1;
	}
	
	snprint_stack_trace(printStr, STRING_SIZE, temp_trace, 0);	
	kfree(temp_trace->entries);
	kfree(temp_trace);

	return printStr;
}

static u32 get_callstack_jhash(struct task_struct *task) {
	char *stackString = getStackString(task);
	u32 hash_entries = jhash(stackString, sizeof(*stackString), 0);
	kfree(stackString);
	return jhash_2words(task->pid, hash_entries, 0);
}

int insert_rb_node(struct rblack_root_node *rt, struct task_latency_info *rb_n) {
	struct rb_node **link = &(rt->node.rb_node); 
	struct rb_node *parent = NULL;
	struct task_latency_info *entry;
	// Traverse the rbtree to find the right place to insert
	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct task_latency_info, latency_node);
		if (rb_n->total_tsc < entry->total_tsc) {
			link = &parent->rb_left;
		} else if (rb_n->total_tsc > entry->total_tsc) {
			link = &parent->rb_right;
		} else {
			return 0;
		}
	}
	// Insert a new node
	rb_link_node(&rb_n->latency_node, parent, link);
	// Re-balance the rbtree if necessary
	rb_insert_color(&rb_n->latency_node, &rt->node);
	return 1;
}

struct task_latency_info* search_rb_node(struct rblack_root_node *rt, u64 total_tsc) {
	struct rb_node *temp = (&rt->node)->rb_node;
	struct task_latency_info *current_node;
	while (temp) {
		current_node = rb_entry(temp, struct task_latency_info, latency_node);
		if (total_tsc < current_node->total_tsc) {
			temp = temp->rb_left;
		} else if (total_tsc > current_node->total_tsc) {
			temp = temp->rb_right;
		} else {
			return current_node;
		}
	}
	return NULL;
}

static int checkTimeAndPrint(struct seq_file *m, void *v) {
	int i = 0;
	struct rblack_root_node *rb_rt_node;	// new root node
	rb_rt_node = kmalloc(sizeof(struct rblack_root_node), GFP_ATOMIC);
	rb_rt_node->node = RB_ROOT;
	// print
	struct rb_node *temp_rb_node = rb_last(&rblack_root->node);
	struct task_latency_info *temp_info = rb_entry(temp_rb_node, struct task_latency_info, latency_node);
	while(!RB_EMPTY_ROOT(&rblack_root->node)) {
		rb_erase(&temp_info->latency_node, &rblack_root->node);
		insert_rb_node(rb_rt_node, temp_info);
		if (!latprof_file) { return -ENOMEM; }
		if (i < MAX_STACK_TRACE_DISPLAY) {
			traceStr = kmalloc(STRING_SIZE * sizeof(*traceStr), GFP_ATOMIC);
			if (traceStr == NULL) { return -1; }
			snprint_stack_trace(traceStr, STRING_SIZE, temp_info->trace, 0);
			seq_printf(m, "PID = %u, COMM = %s, cycles = %llu, entryNum = %i\n%s\n", 
				temp_info->pid, temp_info->comm, temp_info->total_tsc, i, traceStr);
			kfree(traceStr);
		}
		i += 1;
		temp_rb_node = rb_last(&rblack_root->node);
		temp_info = rb_entry(temp_rb_node, struct task_latency_info, latency_node);
	}	
	kfree(rblack_root);	
	rblack_root = rb_rt_node;		 
	return 0;
	//spin_unlock_irq(&rb_lock);	
}

static int latprof_open(struct inode *node, struct file *file) {
	return single_open(file, checkTimeAndPrint, NULL);
}

static const struct file_operations latprof_fops = {
	.owner = THIS_MODULE,
	.open = latprof_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static struct kprobe sleepProbe = {
	.symbol_name = "deactivate_task",
};

static struct kprobe activeProbe = {
	.symbol_name = "activate_task",
};

/* kprobe handler for sleeping tasks */
static int sleep_handler 		(struct kprobe *p, struct pt_regs *pr) {
	int i = 0;
	int exist = 0;
	struct task_latency_info *tempNode;
	struct task_struct *my_task_struct = (struct task_struct*)(pr->si);
	u32 key = get_callstack_jhash(my_task_struct);
	// checking to see if the node already exists
	hash_for_each(lf_hashtable, i, tempNode, stack_node) {
		if (key == tempNode->hash_key) {
			tempNode->start_tsc = rdtsc();
			return 0;
		}
	}	
	
	struct task_latency_info *currTask_info = kmalloc(sizeof(*currTask_info), GFP_ATOMIC);
	if (currTask_info == NULL) { return -1;	} 
	// PID
	currTask_info->pid = my_task_struct->pid;
	// Comm	
	memcpy((void *)currTask_info->comm, (void*)my_task_struct->comm, TASK_COMM_LEN);
	// Stack trace
	currTask_info->trace = kmalloc(sizeof(*currTask_info->trace), GFP_ATOMIC);
	if (currTask_info->trace == NULL) { return -1; }

	currTask_info->trace->entries = kmalloc(MAX_STACK_TRACE * sizeof(*currTask_info->trace->entries), GFP_ATOMIC);
	if (currTask_info->trace->entries == NULL) { return -1; }

	currTask_info->trace->max_entries = MAX_STACK_TRACE;
	currTask_info->trace->nr_entries = 0;
	save_stack_trace_tsk(my_task_struct, currTask_info->trace); 
	// Setting start time
	currTask_info->start_tsc = rdtsc();
	currTask_info->total_tsc = 0;
	// jhash
	currTask_info->hash_key = get_callstack_jhash(my_task_struct);
	// printing
	char *printStr = kmalloc(STRING_SIZE * sizeof(*printStr), GFP_ATOMIC);
	if (printStr == NULL) {	return -1; }
	
	snprint_stack_trace(printStr, STRING_SIZE, currTask_info->trace, 0);
	kfree(printStr);
	//spin_lock_irqs(&ht_lock);
	tl_ht_insert(currTask_info);
	//spin_unlock_irq(&ht_lock);
	return 0;
}

/* kprobe handler for waking up tasks */
static int wake_up_handler 		(struct kprobe *p, struct pt_regs *pr) {
	struct task_struct *my_task_struct = (struct task_struct*)(pr->si);
	u32 key = get_callstack_jhash(my_task_struct);
	struct task_latency_info *node;
	//spin_lock_irqs(&ht_lock);
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
			char *printStr = kmalloc(STRING_SIZE * sizeof(*printStr), GFP_ATOMIC);
			if (printStr == NULL) { return -1; }
			snprint_stack_trace(printStr, STRING_SIZE, trace, 0);
			//spin_unlock_irq(&ht_lock);
			
			//spin_lock_irqs(&rb_lock);
			// red-black tree implementation
			if (search_rb_node(rblack_root, node->total_tsc) != NULL) {
				// Node Exists -> remove, update, and insert --- If Not exist, insert
				rb_erase(&node->latency_node, &rblack_root->node);
			}
			// insert (if exist, increment)
			node->total_tsc += rdtsc() - node->start_tsc;
			while(insert_rb_node(rblack_root, node) == 0) {
				node->total_tsc += 1;
			}
			//spin_unlock_irq(&rb_lock);
			kfree(trace->entries);
			kfree(trace);
			kfree(printStr);
			return 0;
		}
	}
	//spin_unlock_irq(&ht_lock);
	return 0;
}

static int __init latprof_init(void) {
	int sret, aret;	
	startTime = kmalloc(sizeof(*startTime),GFP_KERNEL);
	currTime = kmalloc(sizeof(*currTime), GFP_KERNEL);

	traceStr = kmalloc(STRING_SIZE * sizeof(*traceStr), GFP_KERNEL);	
	latprof_file = proc_create("latprof", 0, NULL, &latprof_fops);
	kfree(traceStr);

	hash_init(lf_hashtable);
	rblack_root = kmalloc(sizeof(struct rblack_root_node), GFP_KERNEL);
	rblack_root->node = RB_ROOT;
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
	return 0; /* return 0 on success, something else on error */
}

static void __exit latprof_exit(void) {
	int i = 0;
	struct task_latency_info *node;
	remove_proc_entry("latprof", NULL);
	kfree(startTime);
	kfree(currTime); 
	unregister_kprobe(&sleepProbe);
	unregister_kprobe(&activeProbe);
	// deacllocate hashtable
	hash_for_each(lf_hashtable, i, node, stack_node) {
		latprof_info("Deleting PID:%u, COMM:%s\n", node->pid, node->comm);
		if (search_rb_node(rblack_root, node->total_tsc) != NULL) {
			latprof_info("PRINTING RBnode PID = %u", node->pid);
			rb_erase(&node->latency_node, &rblack_root->node);
		}		
		kfree(node->trace->entries);
		kfree(node->trace);
		hash_del(&node->stack_node);
		kfree(node);
	}
	kfree(rblack_root);
	latprof_info("###################################################\n");
	latprof_info("############## Latprof exiting ... ################\n");
	latprof_info("###################################################\n");
}

module_init(latprof_init); 	/* latprof_init() will be called at loading the module */
module_exit(latprof_exit); 	/* latprof_exit() will be called at unloading the module */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jinwoo Yom <jinwoo7@vt.edu>");
MODULE_DESCRIPTION("Sample kernel module");

