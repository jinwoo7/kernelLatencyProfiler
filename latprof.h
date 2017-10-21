// Latency top measuring time between sleeping and waking up
#include <linux/kernel.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/seq_file.h>

// define macros for logging
#define PT_REGS_PARM2(x) ((x)->si)
#define MAX_STACK_TRACE 32
#define MAX_STACK_TRACE_DISPLAY 1000

struct task_stack_trace {
	pid_t				pid;
	struct stack_trace 		trace;
	unsigned long 			trace_entries[MAX_STACK_TRACE];
};

struct task_latency_info {
	char 				comm[TASK_COMM_LEN];

	// maintain task call stack using a hash table
	struct task_stack_trace 	task_stack;		// stack trace of the task
	struct hlist_node		stack_node;		// hash node
	u32				hash_key;  		// key of the hash table

	// maintain cumulative latency using a rbtree
	u64 				latency_tsc;	// task sleep clock cycle
	struct rb_node 			latency_node;	// red-black tree node
};

struct task_timer {
	struct hlist_node 		node;			// Hash node for quicker access and update
	pid_t				pid;			// process id that is being timed
	u64				start_tsc;		// The cpu sleeping clock cycle
};

// internal functions 
/* kprobe handler for sleeping tasks */
static int sleep_handler 			(struct kprobe *, struct pt_regs *);
/* kprobe handler for waking up tasks */
static int wake_up_handler 			(struct kprobe *, struct pt_regs *);

static void save_task_stack_trace 	(struct task_struct *, struct task_stack_trace *, int);
static void print_task_stack_trace 	(struct seq_file *, struct task_stack_trace *, const int);
static void print_task_latency_info	(struct seq_file *, struct task_latency_info *);

/* start the cpu timer */
static void start_task_timer		(struct task_struct *);
/* stops the cpu timer */
static void stop_task_timer			(struct task_struct *, u64);
/* deinitialize the timer */
static void deinit_task_time		(void);

/* Updates the task struct with new ellapsed task sleep cycle */
static void update_task_latency_info(struct task_struct *tsk, u64 elapsed_tsc);

static int latprof_stat_open		(struct inode *inode, struct file *file);




