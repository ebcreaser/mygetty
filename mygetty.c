#define _XOPEN_SOURCE 600

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <shadow.h>
#include <crypt.h>
#include <pwd.h>
#include <errno.h>
#include <sys/wait.h>

#define MAXPW 256

static int getty(char *path);
static struct passwd *getpw();

static int
getty(char *path)
{
	int fd;

	if ((fd = open(path, O_RDWR)) < 0) {
		return -1;
	}
	if ((fd = open(path, O_RDWR)) < 0) {
		return -1;
	}
	if (dup2(fd, STDOUT_FILENO) != STDOUT_FILENO) {
		return -1;
	}
	if (dup2(fd, STDIN_FILENO) != STDIN_FILENO) {
		return -1;
	}
	if (dup2(fd, STDERR_FILENO) != STDERR_FILENO) {
		return -1;
	}

	return fd;
}

static struct passwd *
getpw()
{
	struct spwd *sp;
	char user[256];
	char passwd[256];
	char *hash;
	int c, i;

	fputs("Username: ", stdout);
	i = 0;
	while((c = getchar()) != '\n' && c != EOF && i < MAXPW - 1) {
		user[i++] = c;
	}
	user[i] = '\0';
	fputs("Password: ", stdout);
	i = 0;
	while((c = getchar()) != '\n' && c != EOF && i < MAXPW - 1) {
		passwd[i++] = c;
	}
	passwd[i] = '\0';
	if ((sp = getspnam(user)) == NULL) {
		return NULL;
	}
	hash = crypt(passwd, sp->sp_pwdp);
	if (strcmp(hash, sp->sp_pwdp)) {
		fputs("Incorrect\n", stdout);
		return NULL;
	} else {
		fputs("Correct\n", stdout);
		return getpwnam(user);
	}
}

int
main(int argc, char *argv[])
{
	struct passwd *pw;
	int fd;
	pid_t pid;

	if (argc < 2) {
		goto error;
	}
	pid = fork();
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	} else if (pid < 0) {
		goto error;
	}
	if (setsid() < 0) {
		goto error;
	}
	if ((fd = getty(argv[1])) < 0) {
		goto error;
	}
	while(!(pw = getpw()));
	if (!pw) {
		goto error;
	}
	setuid(pw->pw_uid);
	setenv("HOME", pw->pw_dir, 1);
	chdir(pw->pw_dir);
	execl(pw->pw_shell, pw->pw_shell, "--login", (char *) NULL);
	exit(EXIT_SUCCESS);
error:
	exit(EXIT_FAILURE);
}
