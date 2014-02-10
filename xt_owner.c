/*
 * Kernel module to match various things tied to sockets associated with
 * locally generated outgoing packets.
 *
 * (C) 2000 Marc Boucher <marc@mbsi.ca>
 *
 * Copyright © CC Computer Consultants GmbH, 2007 - 2008
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/file.h>
#include <net/sock.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_owner.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/pid_namespace.h>
#include <linux/fdtable.h>
#include <linux/pid.h>

#define XT_OWNER_LIST_SIZE 20

#define XT_OWNER_DEBUG 1

static bool owner_checktask(struct task_struct *task,
			     const struct file *filp)
{
	struct files_struct *files;
	int i;
	
	if (task){	
		get_task_struct(task);
		files = task->files;
		if (files) {
			for(i=0; i < files_fdtable(files)->max_fds; i++) {
				if (fcheck_files(files, i) == filp) {
#ifdef XT_OWNER_DEBUG
					printk("xt_owner: Match on task %d\n",task->pid);
#endif
					put_task_struct(task);
					return true;
				}
			}
		}
		put_task_struct(task);
	}
	return false;
}

static int owner_push_node(struct owner_task_stack *stack, struct task_struct *task) {
	struct task_struct **tmp_nodes;

	if (stack->length == stack->size) {
		tmp_nodes = krealloc(stack->tasks, sizeof(struct task_struct *)
				     * (XT_OWNER_LIST_SIZE*2), GFP_KERNEL);
		if (!tmp_nodes)
			return -1;
		stack->size = XT_OWNER_LIST_SIZE * 2;
		stack->tasks = tmp_nodes;
	}

	(stack->length)++;
	stack->tasks[(stack->length)-1] = task;

	return 0;
}

static struct task_struct *owner_pop_node(struct owner_task_stack *stack) {	
	struct task_struct *tmp;
	
	if (stack->length == 0)
		return NULL;

	tmp = stack->tasks[(stack->length)-1];
	(stack->length)--;
	return tmp;
}

static bool owner_walk_tree(struct owner_task_stack *stack, struct task_struct *task,
			    const struct file *filp) {
	struct task_struct *child_task, *sub_child_task;
	struct list_head *head;
	bool result = false;

	get_task_struct(task);
	if (owner_push_node(stack, task) < 0)
		stack->length = 0;

	while (stack->length > 0) {
		//Pop dell'elemento nella variabile child_task
		child_task = owner_pop_node(stack);
#ifdef XT_OWNER_DEBUG
		printk("xt_owner: Analisys of task %d\n", child_task->pid);
#endif
		if (owner_checktask(child_task, filp)) {
			result = true;
			break;
		}
#ifdef XT_OWNER_DEBUG
		printk("xt_owner: trying to lookup children of task %d\n", child_task->pid);
#endif
		head = &child_task->children;
		list_for_each_entry(sub_child_task, head, sibling) {
			get_task_struct(sub_child_task);
			owner_push_node(stack, sub_child_task);
		}
		put_task_struct(child_task);
	}

	while (stack->length > 0) 
		put_task_struct(owner_pop_node(stack));

	kfree(stack->tasks);
	return result;
}

static bool owner_pid(const struct file *filp, pid_t sid, enum pid_type pidt,
		      struct pid_namespace *pid_ns, bool depth_search, 
		      struct owner_task_stack *stack)
{
	struct task_struct *task;
	struct pid *first_task_pid;
#ifdef XT_OWNER_DEBUG
	printk("xt_owner: Starting xID search\n");
#endif
	rcu_read_lock();
	first_task_pid = find_pid_ns(sid, pid_ns);
	if (first_task_pid) {
		do_each_pid_task(first_task_pid, pidt, task) { 
			if (owner_checktask(task, filp)){
	                                rcu_read_unlock();
                                	return true;
                        }
			if (depth_search) {
				if (owner_walk_tree(stack, task, filp)) {
					rcu_read_unlock();
					return true;
				}
			}
		}
		while_each_pid_task(first_task_pid, pidt, task);
	}
	rcu_read_unlock();
	return false;
}

static bool
owner_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_owner_match_info *info = par->matchinfo;
	const struct file *filp;
	
	if (skb->sk == NULL || skb->sk->sk_socket == NULL)
		return (info->match ^ info->invert) == 0;
	else if (info->match & info->invert & XT_OWNER_SOCKET)
		/*
		 * Socket exists but user wanted ! --socket-exists.
		 * (Single ampersands intended.)
		 */
		return false;

	filp = skb->sk->sk_socket->file;
	if (filp == NULL)
		return ((info->match ^ info->invert) &
		       (XT_OWNER_UID | XT_OWNER_GID | 
			XT_OWNER_PID | XT_OWNER_SID |
			XT_OWNER_PGID| XT_OWNER_PPID)) == 0;

	if (info->match & XT_OWNER_UID)
		if ((filp->f_cred->fsuid >= info->uid_min &&
		    filp->f_cred->fsuid <= info->uid_max) ^
		    !(info->invert & XT_OWNER_UID))
			return false;

	if (info->match & XT_OWNER_GID)
		if ((filp->f_cred->fsgid >= info->gid_min &&
		    filp->f_cred->fsgid <= info->gid_max) ^
		    !(info->invert & XT_OWNER_GID))
			return false;

	if (info->match & XT_OWNER_PID)
		if ((owner_pid(filp, (pid_t) info->pid,
		    PIDTYPE_PID, info->pid_ns, false, NULL) ) ^
		    !(info->invert & XT_OWNER_PID))
			return false;

	if (info->match & XT_OWNER_PPID)
		if ((owner_pid(filp, (pid_t) info->pid,
		    PIDTYPE_PID, info->pid_ns, true,
		    info->stack) ) ^
		    !(info->invert & XT_OWNER_PPID))
			return false;

	if (info->match & XT_OWNER_PGID)
		if ((owner_pid(filp, (pid_t) info->pgid,
		    PIDTYPE_PGID, info->pid_ns, false, NULL)) ^
		    !(info->invert & XT_OWNER_PGID))
			return false;

	if (info->match & XT_OWNER_SID)
                if ((owner_pid(filp, (pid_t) info->sid,
                    PIDTYPE_SID, info->pid_ns, false, NULL)) ^
                    !(info->invert & XT_OWNER_SID))
                        return false;

	return true;
}

static int owner_check(const struct xt_mtchk_param *par)
{
	struct xt_owner_match_info *info = par->matchinfo;
	struct owner_task_stack *stack;

	if (info->match & (XT_OWNER_PID | XT_OWNER_PPID |
	    XT_OWNER_SID | XT_OWNER_PGID))
		info->pid_ns = current->nsproxy->pid_ns;
	
	if (info->match & XT_OWNER_PPID) {
		stack = vmalloc(sizeof(struct owner_task_stack));

		if (!stack)
			return -EINVAL;

		stack->size = XT_OWNER_LIST_SIZE;
		stack->length = 0;
		stack->tasks = kmalloc(
			sizeof(struct task_struct *) * XT_OWNER_LIST_SIZE, GFP_KERNEL);	

		if (!stack->tasks) { /* Memory allocation error */
			vfree(stack);
			return -EINVAL;
		}

		info->stack = stack;
	}

	return 0;
}

static void owner_destroy(const struct xt_mtdtor_param *par)
{
	const struct xt_owner_match_info *info = par->matchinfo;

	if (info->match & XT_OWNER_PPID) {
		kfree((info->stack)->tasks);
		vfree(info->stack);
	}
}


static struct xt_match owner_mt_reg __read_mostly = {
	.name       = "owner",
	.revision   = 1,
	.family     = NFPROTO_UNSPEC,
	.checkentry = owner_check,
	.destroy    = owner_destroy,
	.match      = owner_mt,
	.matchsize  = sizeof(struct xt_owner_match_info),
	.hooks      = (1 << NF_INET_LOCAL_OUT) |
	              (1 << NF_INET_POST_ROUTING),
	.me         = THIS_MODULE,
};

static int __init owner_mt_init(void)
{
	return xt_register_match(&owner_mt_reg);
}

static void __exit owner_mt_exit(void)
{
	xt_unregister_match(&owner_mt_reg);
}

module_init(owner_mt_init);
module_exit(owner_mt_exit);
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>");
MODULE_DESCRIPTION("Xtables: socket owner matching");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_owner");
MODULE_ALIAS("ip6t_owner");
