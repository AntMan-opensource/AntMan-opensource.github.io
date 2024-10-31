






























extern char *escape_json_string(char *str);


enum sync_t {
	SYNC_USERMAP_PLS = 0x40,	 SYNC_USERMAP_ACK = 0x41, SYNC_RECVPID_PLS = 0x42, SYNC_RECVPID_ACK = 0x43, SYNC_GRANDCHILD = 0x44, SYNC_CHILD_FINISH = 0x45, };













int current_stage = STAGE_SETUP;


struct clone_t {
	
	char stack[4096] __attribute__((aligned(16)));
	char stack_ptr[0];

	
	jmp_buf *env;
	int jmpval;
};

struct nlconfig_t {
	char *data;

	
	uint32_t cloneflags;
	char *oom_score_adj;
	size_t oom_score_adj_len;

	
	char *uidmap;
	size_t uidmap_len;
	char *gidmap;
	size_t gidmap_len;
	char *namespaces;
	size_t namespaces_len;
	uint8_t is_setgroup;

	
	uint8_t is_rootless_euid;	
	char *uidmappath;
	size_t uidmappath_len;
	char *gidmappath;
	size_t gidmappath_len;
};










static const char *level_str[] = { "panic", "fatal", "error", "warning", "info", "debug", "trace" };

static int logfd = -1;
static int loglevel = DEBUG;

























int setns(int fd, int nstype)
{
	return syscall(SYS_setns, fd, nstype);
}


static void write_log(int level, const char *format, ...)
{
	char *message = NULL, *stage = NULL, *json = NULL;
	va_list args;
	int ret;

	if (logfd < 0 || level > loglevel)
		goto out;

	va_start(args, format);
	ret = vasprintf(&message, format, args);
	va_end(args);
	if (ret < 0) {
		message = NULL;
		goto out;
	}

	message = escape_json_string(message);

	if (current_stage == STAGE_SETUP)
		stage = strdup("nsexec");
	else ret = asprintf(&stage, "nsexec-%d", current_stage);
	if (ret < 0) {
		stage = NULL;
		goto out;
	}

	ret = asprintf(&json, "{\"level\":\"%s\", \"msg\": \"%s[%d]: %s\"}\n", level_str[level], stage, getpid(), message);
	if (ret < 0) {
		json = NULL;
		goto out;
	}

	
	ssize_t __attribute__((unused)) __res = write(logfd, json, ret);

out:
	free(message);
	free(stage);
	free(json);
}


static int syncfd = -1;










static int write_file(char *data, size_t data_len, char *pathfmt, ...)
{
	int fd, len, ret = 0;
	char path[PATH_MAX];

	va_list ap;
	va_start(ap, pathfmt);
	len = vsnprintf(path, PATH_MAX, pathfmt, ap);
	va_end(ap);
	if (len < 0)
		return -1;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		return -1;
	}

	len = write(fd, data, data_len);
	if (len != data_len) {
		ret = -1;
		goto out;
	}

out:
	close(fd);
	return ret;
}

enum policy_t {
	SETGROUPS_DEFAULT = 0, SETGROUPS_ALLOW, SETGROUPS_DENY, };




static void update_setgroups(int pid, enum policy_t setgroup)
{
	char *policy;

	switch (setgroup) {
	case SETGROUPS_ALLOW:
		policy = "allow";
		break;
	case SETGROUPS_DENY:
		policy = "deny";
		break;
	case SETGROUPS_DEFAULT:
	default:
		
		return;
	}

	if (write_file(policy, strlen(policy), "/proc/%d/setgroups", pid) < 0) {
		
		if (errno != ENOENT)
			bail("failed to write '%s' to /proc/%d/setgroups", policy, pid);
	}
}

static int try_mapping_tool(const char *app, int pid, char *map, size_t map_len)
{
	int child;

	
	if (!app)
		bail("mapping tool not present");

	child = fork();
	if (child < 0)
		bail("failed to fork");

	if (!child) {

		char *argv[MAX_ARGV];
		char *envp[] = { NULL };
		char pid_fmt[16];
		int argc = 0;
		char *next;

		snprintf(pid_fmt, 16, "%d", pid);

		argv[argc++] = (char *)app;
		argv[argc++] = pid_fmt;
		

		while (argc < MAX_ARGV) {
			if (*map == '\0') {
				argv[argc++] = NULL;
				break;
			}
			argv[argc++] = map;
			next = strpbrk(map, "\n ");
			if (next == NULL)
				break;
			*next++ = '\0';
			map = next + strspn(next, "\n ");
		}

		execve(app, argv, envp);
		bail("failed to execv");
	} else {
		int status;

		while (true) {
			if (waitpid(child, &status, 0) < 0) {
				if (errno == EINTR)
					continue;
				bail("failed to waitpid");
			}
			if (WIFEXITED(status) || WIFSIGNALED(status))
				return WEXITSTATUS(status);
		}
	}

	return -1;
}

static void update_uidmap(const char *path, int pid, char *map, size_t map_len)
{
	if (map == NULL || map_len == 0)
		return;

	write_log(DEBUG, "update /proc/%d/uid_map to '%s'", pid, map);
	if (write_file(map, map_len, "/proc/%d/uid_map", pid) < 0) {
		if (errno != EPERM)
			bail("failed to update /proc/%d/uid_map", pid);
		write_log(DEBUG, "update /proc/%d/uid_map got -EPERM (trying %s)", pid, path);
		if (try_mapping_tool(path, pid, map, map_len))
			bail("failed to use newuid map on %d", pid);
	}
}

static void update_gidmap(const char *path, int pid, char *map, size_t map_len)
{
	if (map == NULL || map_len == 0)
		return;

	write_log(DEBUG, "update /proc/%d/gid_map to '%s'", pid, map);
	if (write_file(map, map_len, "/proc/%d/gid_map", pid) < 0) {
		if (errno != EPERM)
			bail("failed to update /proc/%d/gid_map", pid);
		write_log(DEBUG, "update /proc/%d/gid_map got -EPERM (trying %s)", pid, path);
		if (try_mapping_tool(path, pid, map, map_len))
			bail("failed to use newgid map on %d", pid);
	}
}

static void update_oom_score_adj(char *data, size_t len)
{
	if (data == NULL || len == 0)
		return;

	write_log(DEBUG, "update /proc/self/oom_score_adj to '%s'", data);
	if (write_file(data, len, "/proc/self/oom_score_adj") < 0)
		bail("failed to update /proc/self/oom_score_adj");
}


static int child_func(void *arg) __attribute__((noinline));
static int child_func(void *arg)
{
	struct clone_t *ca = (struct clone_t *)arg;
	longjmp(*ca->env, ca->jmpval);
}

static int clone_parent(jmp_buf *env, int jmpval) __attribute__((noinline));
static int clone_parent(jmp_buf *env, int jmpval)
{
	struct clone_t ca = {
		.env = env, .jmpval = jmpval, };


	return clone(child_func, ca.stack_ptr, CLONE_PARENT | SIGCHLD, &ca);
}


static int getenv_int(const char *name)
{
	char *val, *endptr;
	int ret;

	val = getenv(name);
	
	if (val == NULL || *val == '\0')
		return -ENOENT;

	ret = strtol(val, &endptr, 10);
	if (val == endptr || *endptr != '\0')
		bail("unable to parse %s=%s", name, val);
	
	if (ret < 0 || ret > TRACE)
		bail("bad value for %s=%s (%d)", name, val, ret);

	return ret;
}


static void setup_logpipe(void)
{
	int i;

	i = getenv_int("_LIBCONTAINER_LOGPIPE");
	if (i < 0) {
		
		return;
	}
	logfd = i;

	i = getenv_int("_LIBCONTAINER_LOGLEVEL");
	if (i < 0)
		return;
	loglevel = i;
}


static int nsflag(char *name)
{
	if (!strcmp(name, "cgroup"))
		return CLONE_NEWCGROUP;
	else if (!strcmp(name, "ipc"))
		return CLONE_NEWIPC;
	else if (!strcmp(name, "mnt"))
		return CLONE_NEWNS;
	else if (!strcmp(name, "net"))
		return CLONE_NEWNET;
	else if (!strcmp(name, "pid"))
		return CLONE_NEWPID;
	else if (!strcmp(name, "user"))
		return CLONE_NEWUSER;
	else if (!strcmp(name, "uts"))
		return CLONE_NEWUTS;

	
	return 0;
}

static uint32_t readint32(char *buf)
{
	return *(uint32_t *) buf;
}

static uint8_t readint8(char *buf)
{
	return *(uint8_t *) buf;
}

static void nl_parse(int fd, struct nlconfig_t *config)
{
	size_t len, size;
	struct nlmsghdr hdr;
	char *data, *current;

	
	len = read(fd, &hdr, NLMSG_HDRLEN);
	if (len != NLMSG_HDRLEN)
		bail("invalid netlink header length %zu", len);

	if (hdr.nlmsg_type == NLMSG_ERROR)
		bail("failed to read netlink message");

	if (hdr.nlmsg_type != INIT_MSG)
		bail("unexpected msg type %d", hdr.nlmsg_type);

	
	size = NLMSG_PAYLOAD(&hdr, 0);
	current = data = malloc(size);
	if (!data)
		bail("failed to allocate %zu bytes of memory for nl_payload", size);

	len = read(fd, data, size);
	if (len != size)
		bail("failed to read netlink payload, %zu != %zu", len, size);

	
	config->data = data;
	while (current < data + size) {
		struct nlattr *nlattr = (struct nlattr *)current;
		size_t payload_len = nlattr->nla_len - NLA_HDRLEN;

		
		current += NLA_HDRLEN;

		
		switch (nlattr->nla_type) {
		case CLONE_FLAGS_ATTR:
			config->cloneflags = readint32(current);
			break;
		case ROOTLESS_EUID_ATTR:
			config->is_rootless_euid = readint8(current);	
			break;
		case OOM_SCORE_ADJ_ATTR:
			config->oom_score_adj = current;
			config->oom_score_adj_len = payload_len;
			break;
		case NS_PATHS_ATTR:
			config->namespaces = current;
			config->namespaces_len = payload_len;
			break;
		case UIDMAP_ATTR:
			config->uidmap = current;
			config->uidmap_len = payload_len;
			break;
		case GIDMAP_ATTR:
			config->gidmap = current;
			config->gidmap_len = payload_len;
			break;
		case UIDMAPPATH_ATTR:
			config->uidmappath = current;
			config->uidmappath_len = payload_len;
			break;
		case GIDMAPPATH_ATTR:
			config->gidmappath = current;
			config->gidmappath_len = payload_len;
			break;
		case SETGROUP_ATTR:
			config->is_setgroup = readint8(current);
			break;
		default:
			bail("unknown netlink message type %d", nlattr->nla_type);
		}

		current += NLA_ALIGN(payload_len);
	}
}

void nl_free(struct nlconfig_t *config)
{
	free(config->data);
}

void join_namespaces(char *nslist)
{
	int num = 0, i;
	char *saveptr = NULL;
	char *namespace = strtok_r(nslist, ",", &saveptr);
	struct namespace_t {
		int fd;
		char type[PATH_MAX];
		char path[PATH_MAX];
	} *namespaces = NULL;

	if (!namespace || !strlen(namespace) || !strlen(nslist))
		bail("ns paths are empty");

	
	do {
		int fd;
		char *path;
		struct namespace_t *ns;

		
		namespaces = realloc(namespaces, ++num * sizeof(struct namespace_t));
		if (!namespaces)
			bail("failed to reallocate namespace array");
		ns = &namespaces[num - 1];

		
		path = strstr(namespace, ":");
		if (!path)
			bail("failed to parse %s", namespace);
		*path++ = '\0';

		fd = open(path, O_RDONLY);
		if (fd < 0)
			bail("failed to open %s", path);

		ns->fd = fd;
		strncpy(ns->type, namespace, PATH_MAX - 1);
		strncpy(ns->path, path, PATH_MAX - 1);
		ns->path[PATH_MAX - 1] = '\0';
	} while ((namespace = strtok_r(NULL, ",", &saveptr)) != NULL);

	

	for (i = 0; i < num; i++) {
		struct namespace_t *ns = &namespaces[i];
		int flag = nsflag(ns->type);

		write_log(DEBUG, "setns(%#x) into %s namespace (with path %s)", flag, ns->type, ns->path);
		if (setns(ns->fd, flag) < 0)
			bail("failed to setns into %s namespace", ns->type);

		close(ns->fd);
	}

	free(namespaces);
}


extern int ensure_cloned_binary(void);

static inline int sane_kill(pid_t pid, int signum)
{
	if (pid > 0)
		return kill(pid, signum);
	else return 0;
}

void nsexec(void)
{
	int pipenum;
	jmp_buf env;
	int sync_child_pipe[2], sync_grandchild_pipe[2];
	struct nlconfig_t config = { 0 };

	
	setup_logpipe();

	
	pipenum = getenv_int("_LIBCONTAINER_INITPIPE");
	if (pipenum < 0) {
		
		return;
	}

	
	if (ensure_cloned_binary() < 0)
		bail("could not ensure we are a cloned binary");

	
	if (write(pipenum, "", 1) != 1)
		bail("could not inform the parent we are past initial setup");

	write_log(DEBUG, "=> nsexec container setup");

	
	nl_parse(pipenum, &config);

	
	update_oom_score_adj(config.oom_score_adj, config.oom_score_adj_len);

	
	if (config.namespaces) {
		write_log(DEBUG, "set process as non-dumpable");
		if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
			bail("failed to set process as non-dumpable");
	}

	
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sync_child_pipe) < 0)
		bail("failed to setup sync pipe between parent and child");

	
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sync_grandchild_pipe) < 0)
		bail("failed to setup sync pipe between parent and grandchild");

	

	

	current_stage = setjmp(env);
	switch (current_stage) {
		
	case STAGE_PARENT:{
			int len;
			pid_t stage1_pid = -1, stage2_pid = -1;
			bool stage1_complete, stage2_complete;

			
			prctl(PR_SET_NAME, (unsigned long)"runc:[0:PARENT]", 0, 0, 0);
			write_log(DEBUG, "~> nsexec stage-0");

			
			write_log(DEBUG, "spawn stage-1");
			stage1_pid = clone_parent(&env, STAGE_CHILD);
			if (stage1_pid < 0)
				bail("unable to spawn stage-1");

			syncfd = sync_child_pipe[1];
			if (close(sync_child_pipe[0]) < 0)
				bail("failed to close sync_child_pipe[0] fd");

			
			write_log(DEBUG, "-> stage-1 synchronisation loop");
			stage1_complete = false;
			while (!stage1_complete) {
				enum sync_t s;

				if (read(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with stage-1: next state");

				switch (s) {
				case SYNC_USERMAP_PLS:
					write_log(DEBUG, "stage-1 requested userns mappings");

					
					if (config.is_rootless_euid && !config.is_setgroup)
						update_setgroups(stage1_pid, SETGROUPS_DENY);

					
					update_uidmap(config.uidmappath, stage1_pid, config.uidmap, config.uidmap_len);
					update_gidmap(config.gidmappath, stage1_pid, config.gidmap, config.gidmap_len);

					s = SYNC_USERMAP_ACK;
					if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
						sane_kill(stage1_pid, SIGKILL);
						sane_kill(stage2_pid, SIGKILL);
						bail("failed to sync with stage-1: write(SYNC_USERMAP_ACK)");
					}
					break;
				case SYNC_RECVPID_PLS:
					write_log(DEBUG, "stage-1 requested pid to be forwarded");

					
					if (read(syncfd, &stage2_pid, sizeof(stage2_pid)) != sizeof(stage2_pid)) {
						sane_kill(stage1_pid, SIGKILL);
						sane_kill(stage2_pid, SIGKILL);
						bail("failed to sync with stage-1: read(stage2_pid)");
					}

					
					s = SYNC_RECVPID_ACK;
					if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
						sane_kill(stage1_pid, SIGKILL);
						sane_kill(stage2_pid, SIGKILL);
						bail("failed to sync with stage-1: write(SYNC_RECVPID_ACK)");
					}

					
					write_log(DEBUG, "forward stage-1 (%d) and stage-2 (%d) pids to runc", stage1_pid, stage2_pid);
					len = dprintf(pipenum, "{\"stage1_pid\":%d,\"stage2_pid\":%d}\n", stage1_pid, stage2_pid);

					if (len < 0) {
						sane_kill(stage1_pid, SIGKILL);
						sane_kill(stage2_pid, SIGKILL);
						bail("failed to sync with runc: write(pid-JSON)");
					}
					break;
				case SYNC_CHILD_FINISH:
					write_log(DEBUG, "stage-1 complete");
					stage1_complete = true;
					break;
				default:
					bail("unexpected sync value: %u", s);
				}
			}
			write_log(DEBUG, "<- stage-1 synchronisation loop");

			
			syncfd = sync_grandchild_pipe[1];
			if (close(sync_grandchild_pipe[0]) < 0)
				bail("failed to close sync_grandchild_pipe[0] fd");

			write_log(DEBUG, "-> stage-2 synchronisation loop");
			stage2_complete = false;
			while (!stage2_complete) {
				enum sync_t s;

				write_log(DEBUG, "signalling stage-2 to run");
				s = SYNC_GRANDCHILD;
				if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
					sane_kill(stage2_pid, SIGKILL);
					bail("failed to sync with child: write(SYNC_GRANDCHILD)");
				}

				if (read(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with child: next state");

				switch (s) {
				case SYNC_CHILD_FINISH:
					write_log(DEBUG, "stage-2 complete");
					stage2_complete = true;
					break;
				default:
					bail("unexpected sync value: %u", s);
				}
			}
			write_log(DEBUG, "<- stage-2 synchronisation loop");
			write_log(DEBUG, "<~ nsexec stage-0");
			exit(0);
		}
		break;

		
	case STAGE_CHILD:{
			pid_t stage2_pid = -1;
			enum sync_t s;

			
			syncfd = sync_child_pipe[0];
			if (close(sync_child_pipe[1]) < 0)
				bail("failed to close sync_child_pipe[1] fd");

			
			prctl(PR_SET_NAME, (unsigned long)"runc:[1:CHILD]", 0, 0, 0);
			write_log(DEBUG, "~> nsexec stage-1");

			
			if (config.namespaces)
				join_namespaces(config.namespaces);

			
			if (config.cloneflags & CLONE_NEWUSER) {
				write_log(DEBUG, "unshare user namespace");
				if (unshare(CLONE_NEWUSER) < 0)
					bail("failed to unshare user namespace");
				config.cloneflags &= ~CLONE_NEWUSER;

				
				if (config.namespaces) {
					write_log(DEBUG, "temporarily set process as dumpable");
					if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0)
						bail("failed to temporarily set process as dumpable");
				}

				
				write_log(DEBUG, "request stage-0 to map user namespace");
				s = SYNC_USERMAP_PLS;
				if (write(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with parent: write(SYNC_USERMAP_PLS)");

				
				write_log(DEBUG, "request stage-0 to map user namespace");
				if (read(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with parent: read(SYNC_USERMAP_ACK)");
				if (s != SYNC_USERMAP_ACK)
					bail("failed to sync with parent: SYNC_USERMAP_ACK: got %u", s);

				
				if (config.namespaces) {
					write_log(DEBUG, "re-set process as non-dumpable");
					if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
						bail("failed to re-set process as non-dumpable");
				}

				
				if (setresuid(0, 0, 0) < 0)
					bail("failed to become root in user namespace");
			}

			
			write_log(DEBUG, "unshare remaining namespace (except cgroupns)");
			if (unshare(config.cloneflags & ~CLONE_NEWCGROUP) < 0)
				bail("failed to unshare remaining namespaces (except cgroupns)");

			
			write_log(DEBUG, "spawn stage-2");
			stage2_pid = clone_parent(&env, STAGE_INIT);
			if (stage2_pid < 0)
				bail("unable to spawn stage-2");

			
			write_log(DEBUG, "request stage-0 to forward stage-2 pid (%d)", stage2_pid);
			s = SYNC_RECVPID_PLS;
			if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
				sane_kill(stage2_pid, SIGKILL);
				bail("failed to sync with parent: write(SYNC_RECVPID_PLS)");
			}
			if (write(syncfd, &stage2_pid, sizeof(stage2_pid)) != sizeof(stage2_pid)) {
				sane_kill(stage2_pid, SIGKILL);
				bail("failed to sync with parent: write(stage2_pid)");
			}

			
			if (read(syncfd, &s, sizeof(s)) != sizeof(s)) {
				sane_kill(stage2_pid, SIGKILL);
				bail("failed to sync with parent: read(SYNC_RECVPID_ACK)");
			}
			if (s != SYNC_RECVPID_ACK) {
				sane_kill(stage2_pid, SIGKILL);
				bail("failed to sync with parent: SYNC_RECVPID_ACK: got %u", s);
			}

			write_log(DEBUG, "signal completion to stage-0");
			s = SYNC_CHILD_FINISH;
			if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
				sane_kill(stage2_pid, SIGKILL);
				bail("failed to sync with parent: write(SYNC_CHILD_FINISH)");
			}

			
			write_log(DEBUG, "<~ nsexec stage-1");
			exit(0);
		}
		break;

		
	case STAGE_INIT:{
			
			enum sync_t s;

			
			syncfd = sync_grandchild_pipe[0];
			if (close(sync_grandchild_pipe[1]) < 0)
				bail("failed to close sync_grandchild_pipe[1] fd");

			if (close(sync_child_pipe[0]) < 0)
				bail("failed to close sync_child_pipe[0] fd");

			
			prctl(PR_SET_NAME, (unsigned long)"runc:[2:INIT]", 0, 0, 0);
			write_log(DEBUG, "~> nsexec stage-2");

			if (read(syncfd, &s, sizeof(s)) != sizeof(s))
				bail("failed to sync with parent: read(SYNC_GRANDCHILD)");
			if (s != SYNC_GRANDCHILD)
				bail("failed to sync with parent: SYNC_GRANDCHILD: got %u", s);

			if (setsid() < 0)
				bail("setsid failed");

			if (setuid(0) < 0)
				bail("setuid failed");

			if (setgid(0) < 0)
				bail("setgid failed");

			if (!config.is_rootless_euid && config.is_setgroup) {
				if (setgroups(0, NULL) < 0)
					bail("setgroups failed");
			}

			if (config.cloneflags & CLONE_NEWCGROUP) {
				if (unshare(CLONE_NEWCGROUP) < 0)
					bail("failed to unshare cgroup namespace");
			}

			write_log(DEBUG, "signal completion to stage-0");
			s = SYNC_CHILD_FINISH;
			if (write(syncfd, &s, sizeof(s)) != sizeof(s))
				bail("failed to sync with parent: write(SYNC_CHILD_FINISH)");

			
			if (close(sync_grandchild_pipe[0]) < 0)
				bail("failed to close sync_grandchild_pipe[0] fd");

			
			nl_free(&config);

			
			write_log(DEBUG, "<= nsexec container setup");
			write_log(DEBUG, "booting up go runtime ...");
			return;
		}
		break;
	default:
		bail("unknown stage '%d' for jump value", current_stage);
	}

	
	bail("should never be reached");
}
