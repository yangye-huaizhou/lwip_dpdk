/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>

  
#include "socket_client.h"

#define NETMASK "255.255.255.0"
#define GATEWAY "172.168.0.0"
#define IP_ADDR "172.168.0.2"


/* (manual) host IP configuration */
static ip_addr_t ipaddr, netmask, gw;

/* nonstatic debug cmd option, exported in lwipopts.h */
unsigned char debug_flags;


static void
tcpip_init_done(void *arg)
{
  sys_sem_t *sem;
  sem = (sys_sem_t *)arg;
  init_netifs();
  sys_sem_signal(sem);
}

/*-----------------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------------*/
#if LWIP_RAW
static void tcp_client_thread(void * arg) {
    prctl(PR_SET_NAME,"tcp client thread");
    LWIP_UNUSED_ARG(arg);
    char msg[] = "hello, you are connected!\n";
	struct sockaddr_in server_addr;
	int sock_fd;

	sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd == -1) {
		printf("failed to create sock_fd!\n");
        exit(0);
	}
    memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("172.168.0.1");

	server_addr.sin_port = htons(5000);

	connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
    while (1) {
        send(sock_fd, (char *)msg, sizeof(msg), 0);
		sleep(2);
	}
//	close(sock_fd);
}

#endif

struct netif netif;

static void
init_netifs(void)
{
   
  netif_set_default(netif_add(&netif, &ipaddr, &netmask, &gw, NULL, dpdk_device_init,
                  tcpip_input));
  netif_set_up(&netif);

}

/*-----------------------------------------------------------------------------------*/
static void
main_thread(void *arg)
{
  prctl(PR_SET_NAME,"main thread");
  sys_sem_t sem;
  LWIP_UNUSED_ARG(arg);

  netif_init();

  if(sys_sem_new(&sem, 0) != ERR_OK) {
    LWIP_ASSERT("Failed to create semaphore", 0);
  }
  tcpip_init(tcpip_init_done, &sem);
  sys_sem_wait(&sem);
  printf("TCP/IP initialized.\n");

#if LWIP_RAW
  /** @todo remove dependency on RAW PCB support */
  sys_thread_new("tcp_client", tcp_client_thread, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
#endif

  printf("Applications started.\n");


#ifdef MEM_PERF
  mem_perf_init("/tmp/memstats.client");
#endif /* MEM_PERF */

  /* Block forever. */
  sys_sem_wait(&sem);
}
/*-----------------------------------------------------------------------------------*/
int
main(int argc, char **argv)
{
  int ret = 0;
  struct in_addr inaddr;

  ret = init_dpdk(argc, argv);
  argc -= ret;
  argv += ret;
  if (ret < 0){
    return 0;
  }

  inet_aton(IP_ADDR, &inaddr);
  ipaddr.addr = inaddr.s_addr;
  inet_aton(GATEWAY, &inaddr);
  gw.addr = inaddr.s_addr;
  inet_aton(NETMASK, &inaddr);
  netmask.addr = inaddr.s_addr;


  char ip_str[16] = {0}, nm_str[16] = {0}, gw_str[16] = {0};

  /* startup defaults (may be overridden by one or more opts) */
  //debug_flags |= LWIP_DBG_OFF;
  /* use debug flags defined by debug.h */
  debug_flags |= (LWIP_DBG_ON|LWIP_DBG_TRACE|LWIP_DBG_STATE|LWIP_DBG_FRESH|LWIP_DBG_HALT);
 
  inaddr.s_addr = ipaddr.addr;
  strncpy(ip_str,inet_ntoa(inaddr),sizeof(ip_str));
  inaddr.s_addr = netmask.addr;
  strncpy(nm_str,inet_ntoa(inaddr),sizeof(nm_str));
  inaddr.s_addr = gw.addr;
  strncpy(gw_str,inet_ntoa(inaddr),sizeof(gw_str));
  printf("Host at %s mask %s gateway %s\n", ip_str, nm_str, gw_str);

#ifdef PERF
  perf_init("/tmp/tcp_proxy.perf");
#endif /* PERF */

  printf("System initialized.\n");
  sys_thread_new("main_thread", main_thread, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
  pause();
  return 0;
}
/*-----------------------------------------------------------------------------------*/
