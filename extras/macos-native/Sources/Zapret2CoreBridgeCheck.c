#include "Zapret2CoreBridge.h"

#include <stdio.h>

int main(int argc, char **argv)
{
	char errbuf[512];
	const char *config_file = argc > 1 ? argv[1] : NULL;
	int rc = zapret2_mac_core_init(config_file, errbuf, sizeof(errbuf));

	if (rc == 0)
	{
		printf("zapret2 core bridge init: ok\n");
		printf("%s\n", errbuf);
		zapret2_mac_core_shutdown();
		return 0;
	}

	printf("zapret2 core bridge init: failed\n");
	printf("%s\n", errbuf);
	zapret2_mac_core_shutdown();
	return 1;
}
