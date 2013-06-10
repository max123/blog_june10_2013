#!/usr/sbin/dtrace -qs

#pragma D option temporal

syscall::read:entry
/pid == $target/
{
  printf("read request %d bytes from file = %s\n", arg2, fds[arg0].fi_pathname);
}

syscall::write:entry
/pid == $target/
{
	printf("write request %d bytes to file = %s\n", arg2, fds[arg0].fi_pathname);
}

syscall::unlink*:entry
/pid == $target/
{
	printf("unlinking %s\n", copyinstr(arg0));
}
