#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>

#ifndef UTUN_OPT_IFNAME
#define UTUN_OPT_IFNAME 2
#endif

int main(void)
{
	int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (fd < 0)
	{
		fprintf(stderr, "utun socket failed: %s\n", strerror(errno));
		return 1;
	}

	struct ctl_info info;
	memset(&info, 0, sizeof(info));
	snprintf(info.ctl_name, sizeof(info.ctl_name), "%s", "com.apple.net.utun_control");
	if (ioctl(fd, CTLIOCGINFO, &info) < 0)
	{
		fprintf(stderr, "utun control lookup failed: %s\n", strerror(errno));
		close(fd);
		return 1;
	}

	struct sockaddr_ctl address;
	memset(&address, 0, sizeof(address));
	address.sc_len = sizeof(address);
	address.sc_family = AF_SYSTEM;
	address.ss_sysaddr = AF_SYS_CONTROL;
	address.sc_id = info.ctl_id;
	address.sc_unit = 0;

	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0)
	{
		fprintf(stderr, "utun connect failed: %s\n", strerror(errno));
		close(fd);
		return 1;
	}

	char ifname[64];
	socklen_t ifname_len = sizeof(ifname);
	if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) < 0)
	{
		fprintf(stderr, "utun interface name lookup failed: %s\n", strerror(errno));
		close(fd);
		return 1;
	}

	printf("utun available: %s\n", ifname);
	close(fd);
	return 0;
}
