#ifndef _XT_OWNER_MATCH_H
#define _XT_OWNER_MATCH_H

#include <linux/types.h>

#ifdef __KERNEL__
#include <linux/pid_namespace.h>
#include <linux/sched.h>
#include <linux/list.h>

struct owner_task_stack {
	struct task_struct **tasks;
	size_t length;
	size_t size;
};

#endif

enum {
	XT_OWNER_UID    = 1 << 0,
	XT_OWNER_GID    = 1 << 1,
	XT_OWNER_SOCKET = 1 << 2,
	XT_OWNER_PID	= 1 << 3,
	XT_OWNER_SID	= 1 << 4,
	XT_OWNER_PGID	= 1 << 5,
	XT_OWNER_PPID	= 1 << 6,
};

struct xt_owner_match_info {
	__u32 uid_min, uid_max;
	__u32 gid_min, gid_max;
	__u32 pid;
	__u32 pgid;
	__u32 sid;
	__u8 match, invert;
	
	/* Used internally by the kernel */
#ifdef __KERNEL__
        struct pid_namespace *pid_ns;
	struct owner_task_stack *stack;
#else
        void *pid_ns;
	void *stack;
#endif
};

#endif /* _XT_OWNER_MATCH_H */
