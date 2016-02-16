/*
 * Fetchmail notification IMAP plugin for Dovecot
 *
 * Copyright (C) 2007 Guillaume Chazarain <guichaz@yahoo.fr>
 * - original version named wake_up_fetchmail.c
 *
 * Copyright (C) 2009-2013 Peter Marschall <peter@adpm.de>
 * - adaptions to dovecot 1.1, 1.2 [now deprecated], 2.0, 2.1 & 2.2
 * - rename to fetchmail_wakeup.c
 * - configuration via dovecot.config
 *
 * License: LGPL v2.1
 *
 */

#include "lib.h"
#include "imap-client.h"
#include "mail-user.h"
#include "module-context.h"
#include "mail-storage-hooks.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>

/* make sure only one API version is defined (prefer higher ones) */
#if defined(DOVECOT_PLUGIN_API_2_1)
#  undef   DOVECOT_PLUGIN_API_2_0
typedef    void   handler_t;
#elif defined(DOVECOT_PLUGIN_API_2_0)
#  warning "======== Using Dovecot 2.0 plugin API ========"
typedef    bool  handler_t;
#else
#  define  DOVECOT_PLUGIN_API_2_1
#  warning "======== Defaulting to Dovecot 2.1+ plugin API ========"
typedef    void   handler_t;
#endif


#define FETCHMAIL_INTERVAL	60

#define FETCHMAIL_WAKEUP_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fetchmail_wakeup_user_module)

struct fetchmail_wakeup_user {
	union mail_user_module_context module_ctx;

  long fetchmail_interval;
	const char *fetchmail_helper;
	const char *fetchmail_pidfile;
  const char *last_run_path;
};

static MODULE_CONTEXT_DEFINE_INIT(fetchmail_wakeup_user_module, &mail_user_module_register);

/* data structure for commands to be overridden */
struct overrides {
	const char *name;		/* the IMAPv4 command name */
	struct command orig_cmd;	/* copy of the original command's data structure */
};


/* commands that can be overridden */
static struct overrides cmds[] = {
	{ "IDLE",   {} },
	{ "NOOP",   {} },
	{ "STATUS", {} },
	{ "NOTIFY", {} },
	{ NULL,     {} }
};


/*
 * Get a interval value from config and parse it into a number (with fallback for failures)
 */
static long getenv_interval(struct mail_user *user, const char *name, long fallback)
{
	if (name != NULL) {
		const char *value_as_str = mail_user_plugin_getenv(user, name);

		if (value_as_str != NULL) {
			long value;

			if ((str_to_long(value_as_str, &value) < 0) || (value <= 0)) {
				i_warning("fetchmail_wakeup: %s must be a positive number", name);
				return fallback;
			}
			else
				return value;
		}
	}
	return fallback;
}

static time_t read_time_from_file(const char *path)
{
    FILE *fp;
    if (0 != (fp = fopen(path, "r")))
    {
      time_t result;
      
      if (1 == fscanf(fp, "%ld", &result))
      {
        fclose(fp);
        return result;
      }
      else
      {
        i_error("fetchmail_wakeup: coult not read time from file %s: %s", path, strerror(errno));
      }
      
      fclose(fp);
    }
    
#if defined(FETCHMAIL_WAKEUP_DEBUG)
  i_debug("fetchmail_wakeup: could not read file %s", path);
#endif
    
    return 0;
}

static void write_time_to_file(time_t time, const char *path)
{
    FILE *fp;
    if (0 != (fp = fopen(path, "w")))
    {
      fprintf(fp, "%ld", time);
      fclose(fp);
    }
    else
    {
      i_error("fetchmail_wakeup: coult not write file %s: %s", path, strerror(errno));
    }
}


/*
 * Don't bother waking up fetchmail too often
 */
static bool ratelimit(struct fetchmail_wakeup_user *muser)
{
  time_t last_run = read_time_from_file(muser->last_run_path);
  time_t now = time(NULL);
  time_t delta = (now - last_run);
  
  if (delta > muser->fetchmail_interval)
  {
    i_info("fetchmail_wakeup: %ld seconds since last run", (long)delta);
    
    write_time_to_file(now, muser->last_run_path);
    return FALSE;
  }

#if defined(FETCHMAIL_WAKEUP_DEBUG)
  i_debug("fetchmail_wakeup: %ld seconds since last run", (long)delta);
#endif

	return TRUE;
}


/*
 * Send a signal to fetchmail or call a helper to awaken fetchmail
 */
static void fetchmail_wakeup(struct client_command_context *ctx)
{
	struct client *client = ctx->client;

	/* make sure client->user is defined */
	if (client == NULL || client->user == NULL)
		return;

	struct fetchmail_wakeup_user *muser = FETCHMAIL_WAKEUP_USER_CONTEXT(client->user);

	if (ratelimit(muser))
		return;

	/* read config variables depending on the session */
	const char *fetchmail_helper = muser->fetchmail_helper;
	const char *fetchmail_pidfile = muser->fetchmail_pidfile;

#if defined(FETCHMAIL_WAKEUP_DEBUG)
	i_debug("fetchmail_wakeup: rate limit passed for %s.", ctx->name);
#endif

	/* if a helper application is defined, then call it */
	if ((fetchmail_helper != NULL) && (*fetchmail_helper != '\0')) {
		pid_t pid;
		int status;
		char *const *argv;

		i_info("fetchmail_wakeup: executing %s.", fetchmail_helper);

		switch (pid = fork()) {
			case -1:	// fork failed
				i_warning("fetchmail_wakeup: fork() failed");
				return;
			case 0:		// child
				argv = (char *const *) t_strsplit_spaces(fetchmail_helper, " ");
				if ((argv != NULL) && (*argv != NULL)) {
					execv(argv[0], argv);
					i_warning("fetchmail_wakeup: execv(%s) failed: %s",
						argv[0], strerror(errno));
					exit(1);
				}
				else {
					i_warning("fetchmail_wakeup: illegal fetchmail_helper");
					exit(1);
				}
			default:	// parent
				waitpid(pid, &status, 0);
		}
	}
	/* otherwise if a pid file name is given, signal fetchmail with that pid */
	else if ((fetchmail_pidfile != NULL) && (*fetchmail_pidfile != '\0')) {
		FILE *pidfile = fopen(fetchmail_pidfile, "r");

#if defined(FETCHMAIL_WAKEUP_DEBUG)
		i_debug("fetchmail_wakeup: sending SIGUSR1 to process given in %s.", fetchmail_pidfile);
#endif

		if (pidfile) {
			pid_t pid = 0;

			if ((fscanf(pidfile, "%d", &pid) == 1) && (pid > 1))
				kill(pid, SIGUSR1);
			else
				i_warning("fetchmail_wakeup: error reading valid pid from %s",
					fetchmail_pidfile);
			fclose(pidfile);
		}
		else {
			i_warning("fetchmail_wakeup: error opening %s",
				 fetchmail_pidfile);
		}
	}
	/* otherwise warn on missing configuration */
	else {
		i_warning("fetchmail_wakeup: neither fetchmail_pidfile nor fetchmail_helper given");
	}
}

static void fetchmail_wakeup_mail_user_created(struct mail_user *user)
{
	struct fetchmail_wakeup_user *muser;

	muser = p_new(user->pool, struct fetchmail_wakeup_user, 1);
	MODULE_CONTEXT_SET(user, fetchmail_wakeup_user_module, muser);

	muser->fetchmail_interval = getenv_interval(user, "fetchmail_interval", FETCHMAIL_INTERVAL);
	muser->fetchmail_helper = mail_user_plugin_getenv(user, "fetchmail_helper");
	muser->fetchmail_pidfile = mail_user_plugin_getenv(user, "fetchmail_pidfile");
	muser->last_run_path = mail_user_home_expand(user, "~/fetchmail_wakeup_last_run");

#if defined(FETCHMAIL_WAKEUP_DEBUG)
  i_debug("fetchmail_wakeup: fetchmail_interval(%d) %ld for %s => %s.", getpid(), muser->fetchmail_interval, user->username, muser->last_run_path);
#endif
}

/*
 * IMAPv4 command wrapper / pre-command hook callback:
 * - Dovecot 2.0: call fetchmail_wakeup & daisy-chain to the IMAP function call
 * - Dovecot 2.1+: simply call fetchmail_wakeup, as Dovecot 2.1+ has command hooks
 */
static handler_t fetchmail_wakeup_cmd(struct client_command_context *ctx)
{
	if (ctx != NULL && ctx->name != NULL) {
		int i;

		for (i = 0; cmds[i].name != NULL; i++) {
			if (strcasecmp(cmds[i].name, ctx->name) == 0) {

#if defined(FETCHMAIL_WAKEUP_DEBUG)
				i_debug("fetchmail_wakeup: intercepting %s.", cmds[i].name);
#endif

				/* try to wake up fetchmail */
				fetchmail_wakeup(ctx);

#if defined(DOVECOT_PLUGIN_API_2_0)
				/* daisy chaining: call original IMAPv4 command handler */
				return ((cmds[i].orig_cmd.func != NULL)
					? cmds[i].orig_cmd.func(ctx)
					: FALSE);
#else
				break;
#endif
			}
		}
	}
#if defined(DOVECOT_PLUGIN_API_2_0)
	return FALSE;
#endif
}


/*
 * IMAPv4 post-command hook callback:
 * - Dovecot 2.1+ (only): required (the hook handlers don't check for NULL), but not used
 */
static handler_t fetchmail_wakeup_null(struct client_command_context *ctx)
{
        /* unused */
}

static struct mail_storage_hooks fetchmail_wakeup_mail_storage_hooks = {
  .mail_user_created = fetchmail_wakeup_mail_user_created,
};

/*
 * Plugin init:
 * - Dovecot 2.0: store original IMAPv4 handler functions and replace it with my own
 * - Dovecot 2.1+: register callback functions into the into command hook chain
 */
void fetchmail_wakeup_plugin_init(struct module *module)
{
#if defined(DOVECOT_PLUGIN_API_2_1)
	command_hook_register(fetchmail_wakeup_cmd, fetchmail_wakeup_null);
	mail_storage_hooks_add(module, &fetchmail_wakeup_mail_storage_hooks);
#elif defined(DOVECOT_PLUGIN_API_2_0)
	int i;

	/* replace IMAPv4 command handlers by our own */
	for (i = 0; cmds[i].name != NULL; i++) {
		struct command *orig_cmd_ptr = command_find(cmds[i].name);

		if (orig_cmd_ptr != NULL) {
			memcpy(&cmds[i].orig_cmd, orig_cmd_ptr, sizeof(struct command));

			command_unregister(cmds[i].name);
			command_register(cmds[i].name, fetchmail_wakeup_cmd, cmds[i].orig_cmd.flags);
		}
	}
#endif

#if defined(FETCHMAIL_WAKEUP_DEBUG)
	i_debug("fetchmail_wakeup: start intercepting IMAP commands.");
#endif
}

/*
 * Plugin deinit:
 * - Dovecot 2.0: restore dovecot's original IMAPv4 handler functions
 * - Dovecot 2.1+: un-register previously registered callback functions
 */
void fetchmail_wakeup_plugin_deinit(void)
{
#if defined(DOVECOT_PLUGIN_API_2_1)
	command_hook_unregister(fetchmail_wakeup_cmd, fetchmail_wakeup_null);
	mail_storage_hooks_remove(&fetchmail_wakeup_mail_storage_hooks);
#elif defined(DOVECOT_PLUGIN_API_2_0)
	int i;

	/* restore previous IMAPv4 command handlers */
	for (i = 0; cmds[i].name != NULL; i++) {
		command_unregister(cmds[i].name);
		command_register(cmds[i].orig_cmd.name, cmds[i].orig_cmd.func, cmds[i].orig_cmd.flags);
	}
#endif

#if defined(FETCHMAIL_WAKEUP_DEBUG)
	i_debug("fetchmail_wakeup: stop intercepting IMAP commands.");
#endif
}


/*
 * declare dependency on IMAP
 */
const char fetchmail_wakeup_plugin_binary_dependency[] = "imap";

/* EOF */
