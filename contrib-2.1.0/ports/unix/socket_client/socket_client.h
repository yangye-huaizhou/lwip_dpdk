#include "lwip/sockets.h"
#include "lwip/err.h"
#include "lwip/opt.h"
#include "lwip/init.h"
#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/sys.h"
#include "lwip/stats.h"
#include "lwip/inet_chksum.h"
#include "lwip/tcpip.h"
//#include "netif/tapif.h"
//#include "netif/pcapif.h"
#include "lwip/ip_addr.h"
#include "arch/perf.h"
#if LWIP_RAW
#include "lwip/icmp.h"
#include "lwip/raw.h"
#endif
#include "netif/dpdkif.h"
static void init_netifs(void);
int main(int argc, char **argv);