/*
 *	libxt_owner - iptables addon for xt_owner
 *
 *	Copyright © CC Computer Consultants GmbH, 2007 - 2008
 *	Jan Engelhardt <jengelh@computergmbh.de>
 */
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <xtables.h>
#include "xt_owner.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#endif

/*
 *	Note: "UINT32_MAX - 1" is used in the code because -1 is a reserved
 *	UID/GID value anyway.
 */

enum {
	O_USER = 0,
	O_GROUP,
	O_SOCK_EXISTS,
	O_PROCESS,
	O_PPROCESS,
	O_SESSION,
	O_PROCESSGROUP,
};

static void owner_mt_help(void)
{
	printf(
"owner match options:\n"
"[!] --uid-owner userid[-userid]      Match local UID\n"
"[!] --gid-owner groupid[-groupid]    Match local GID\n"
"[!] --pid-owner processid            Match local PID\n"
"[!] --sid-owner sessionid            Match local SID\n"
"[!] --pgid-owner processgroupid      Match local PGID\n"
"[!] --ppid-owner processid           Match local PID and childrens\n"
"[!] --socket-exists                  Match if socket exists\n");
}

static const struct xt_option_entry owner_mt_opts[] = {
	{.name = "uid-owner", .id = O_USER, .type = XTTYPE_STRING,
	 .flags = XTOPT_INVERT},
	{.name = "gid-owner", .id = O_GROUP, .type = XTTYPE_STRING,
	 .flags = XTOPT_INVERT},
	{.name = "socket-exists", .id = O_SOCK_EXISTS, .type = XTTYPE_NONE,
	 .flags = XTOPT_INVERT},
	{.name = "pid-owner", .id = O_PROCESS, .type = XTTYPE_UINT32,
	 .flags = XTOPT_INVERT},
	{.name = "ppid-owner", .id = O_PPROCESS, .type = XTTYPE_UINT32,
	 .flags = XTOPT_INVERT},
	{.name = "sid-owner", .id = O_SESSION, .type = XTTYPE_UINT32,
	 .flags = XTOPT_INVERT},
	{.name = "pgid-owner", .id = O_PROCESSGROUP, .type = XTTYPE_UINT32,
	 .flags = XTOPT_INVERT},
	/*{.name = "cmd-owner", .id = O_COMM, .type = XTTYPE_STRING,
	 .flags = XTOPT_INVERT},*/
	XTOPT_TABLEEND,
};

static void owner_parse_range(const char *s, unsigned int *from,
                              unsigned int *to, const char *opt)
{
	char *end;

	/* -1 is reversed, so the max is one less than that. */
	if (!xtables_strtoui(s, &end, from, 0, UINT32_MAX - 1))
		xtables_param_act(XTF_BAD_VALUE, "owner", opt, s);
	*to = *from;
	if (*end == '-' || *end == ':')
		if (!xtables_strtoui(end + 1, &end, to, 0, UINT32_MAX - 1))
			xtables_param_act(XTF_BAD_VALUE, "owner", opt, s);
	if (*end != '\0')
		xtables_param_act(XTF_BAD_VALUE, "owner", opt, s);
}

static void owner_mt_parse(struct xt_option_call *cb)
{
	struct xt_owner_match_info *info = cb->data;
	struct passwd *pwd;
	struct group *grp;
	unsigned int from, to;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_USER:
		if ((pwd = getpwnam(cb->arg)) != NULL)
			from = to = pwd->pw_uid;
		else
			owner_parse_range(cb->arg, &from, &to, "--uid-owner");
		if (cb->invert)
			info->invert |= XT_OWNER_UID;
		info->match  |= XT_OWNER_UID;
		info->uid_min = from;
		info->uid_max = to;
		break;

	case O_GROUP:
		if ((grp = getgrnam(cb->arg)) != NULL)
			from = to = grp->gr_gid;
		else
			owner_parse_range(cb->arg, &from, &to, "--gid-owner");
		if (cb->invert)
			info->invert |= XT_OWNER_GID;
		info->match  |= XT_OWNER_GID;
		info->gid_min = from;
		info->gid_max = to;
		break;

	case O_SOCK_EXISTS:
		if (cb->invert)
			info->invert |= XT_OWNER_SOCKET;
		info->match |= XT_OWNER_SOCKET;
		break;

	case O_PROCESS:
		owner_parse_range(cb->arg, &from, &to, "--pid-owner");
                if (cb->invert)
                        info->invert |= XT_OWNER_PID;
                info->match |= XT_OWNER_PID;
		info->pid = from;
                break;

	case O_PPROCESS:
		owner_parse_range(cb->arg, &from, &to, "--ppid-owner");
		if (cb->invert)
			info->invert |= XT_OWNER_PPID;
		info->match |= XT_OWNER_PPID;
		info->pid = from;
		break;

        case O_SESSION:
		owner_parse_range(cb->arg, &from, &to, "--sid-owner");
                if (cb->invert)
                        info->invert |= XT_OWNER_SID;
                info->match |= XT_OWNER_SID;
		info->sid = from;
                break;

        case O_PROCESSGROUP:
		owner_parse_range(cb->arg, &from, &to, "--pgid-owner");
		if (cb->invert)
			info->invert |= XT_OWNER_PGID;
		info->match |= XT_OWNER_PGID;
		info->pgid = from;
		break;


        /*case O_COMM:
		if (strlen(cb->arg) > sizeof(info->comm))
			xtables_error(PARAMETER_PROBLEM, "owner match: command "
				      "\"%s\" too long, max. %zu characters",
				      cb->arg, sizeof(info->comm));

		info->comm[sizeof(info->comm)-1] = '\0';
		strncpy(info->comm, cb->arg, sizeof(info->comm));

                if (cb->invert)
                        info->invert |= XT_OWNER_COMM;
                info->match |= XT_OWNER_COMM;
                break;*/
	}
}

static void owner_mt_check(struct xt_fcheck_call *cb)
{
	if (cb->xflags == 0)
		xtables_error(PARAMETER_PROBLEM, "owner: At least one of "
		           "--uid-owner, --gid-owner, --pid-owner,"
			   "--sid-owner, --ppid-owner, --pgid-owner"
			   "or --socket-exists is required");
}

static void
owner_mt_print_item(const struct xt_owner_match_info *info, const char *label,
                    uint8_t flag, bool numeric)
{
	if (!(info->match & flag))
		return;
	if (info->invert & flag)
		printf(" !");
	printf(" %s", label);

	switch (info->match & flag) {
	case XT_OWNER_UID:
		if (info->uid_min != info->uid_max) {
			printf(" %u-%u", (unsigned int)info->uid_min,
			       (unsigned int)info->uid_max);
			break;
		} else if (!numeric) {
			const struct passwd *pwd = getpwuid(info->uid_min);

			if (pwd != NULL && pwd->pw_name != NULL) {
				printf(" %s", pwd->pw_name);
				break;
			}
		}
		printf(" %u", (unsigned int)info->uid_min);
		break;

	case XT_OWNER_GID:
		if (info->gid_min != info->gid_max) {
			printf(" %u-%u", (unsigned int)info->gid_min,
			       (unsigned int)info->gid_max);
			break;
		} else if (!numeric) {
			const struct group *grp = getgrgid(info->gid_min);

			if (grp != NULL && grp->gr_name != NULL) {
				printf(" %s", grp->gr_name);
				break;
			}
		}
		printf(" %u", (unsigned int)info->gid_min);
		break;

	case XT_OWNER_PID:
	case XT_OWNER_PPID:
		printf(" %u", (unsigned int)info->pid);
		break;

	case XT_OWNER_SID:
		printf(" %u", (unsigned int)info->sid);
		break;

	case XT_OWNER_PGID:
		printf(" %u", (unsigned int)info->pgid);
		break;

	/*case XT_OWNER_COMM:
		printf(" %.*s", (int)sizeof(info->comm), info->comm);
		break;*/
	}
}

static void owner_mt_print(const void *ip, const struct xt_entry_match *match,
                           int numeric)
{
	const struct xt_owner_match_info *info = (void *)match->data;

	owner_mt_print_item(info, "owner socket exists", XT_OWNER_SOCKET, numeric);
	owner_mt_print_item(info, "owner UID match",     XT_OWNER_UID,    numeric);
	owner_mt_print_item(info, "owner GID match",     XT_OWNER_GID,    numeric);
	owner_mt_print_item(info, "owner PID match",     XT_OWNER_PID,    numeric);
	owner_mt_print_item(info, "owner PPID match",    XT_OWNER_PPID,   numeric);
	owner_mt_print_item(info, "owner SID match",     XT_OWNER_SID,    numeric);
	owner_mt_print_item(info, "owner PGID match",    XT_OWNER_PGID,   numeric);
}

static void owner_mt_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_owner_match_info *info = (void *)match->data;

	owner_mt_print_item(info, "--socket-exits", XT_OWNER_SOCKET, true);
	owner_mt_print_item(info, "--uid-owner", XT_OWNER_UID, true);
	owner_mt_print_item(info, "--gid-owner", XT_OWNER_GID, true);
	owner_mt_print_item(info, "--pid-owner", XT_OWNER_PID, true);
	owner_mt_print_item(info, "--ppid-owner", XT_OWNER_PPID, true);
	owner_mt_print_item(info, "--sid-owner", XT_OWNER_SID, true);
	owner_mt_print_item(info, "--pgid-owner", XT_OWNER_PGID, true);
}

static struct xtables_match owner_mt_reg[] = {
	{
		.version       = XTABLES_VERSION,
		.name          = "owner",
		.revision      = 1,
		.family        = NFPROTO_UNSPEC,
		.size          = XT_ALIGN(sizeof(struct xt_owner_match_info)),
		.userspacesize = XT_ALIGN(offsetof(struct xt_owner_match_info, pid_ns)),
		.help          = owner_mt_help,
		.x6_parse      = owner_mt_parse,
		.x6_fcheck     = owner_mt_check,
		.print         = owner_mt_print,
		.save          = owner_mt_save,
		.x6_options    = owner_mt_opts,
	},
};

void _init(void)
{
	xtables_register_matches(owner_mt_reg, ARRAY_SIZE(owner_mt_reg));
}
