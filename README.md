# lwip_dpdk
DPDK accelerated lwip userspace protocol stack, built based on lwip-2.1.2, dpdk-stable-17.11.9.

### What's the difference?

We made **no** modification to DPDK and lwip, but only add a kind of ```dpdkif``` device in the directory ```contrib-2.1.0/ports/unix/port/netif/```. So the lwip protocol stack can use DPDK driver to receive and send packets. That will make lwip a "real user space" protocol stack.

We also wrote a socket application in ```/ports/unix/socket_client```(client) and ```/ports/unix/socket_server```(server). So you can just follow the logical in this program to write your own applications.

Currently, we bind the dpdk worker thread to logical core 1. Other threads, like "tcpipthread", are not pinned to any specifical core. So please make sure you have at least 2 CPU cores to run this program.


### Usage

To run the application, you first need to compile the DPDK library (here we use dpdk-stable-17.11.9 version):

```
cd ${path_to_dpdk}
make install T=x86_64-native-linuxapp-gcc DESTDIR=install
```
Then use command to initialize hugepage memory and bind NIC (we take the vfio-pci driver for example, other informantion can be found in Intel DPDK website; eth3 is the interface that you want to bind to the DPDK driver):
```
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge
echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
modprobe vfio-pci
chmod a+x /dev/vfio
chmod 0666 /dev/vfio/*
ifconfig eth3 down
./usertools/dpdk-devbind.py --bind=vfio-pci eth3
```

After every thing is finished, compile the application.
Make a "build" directory in ```/ports/unix/socket_server/``` with command:

```
cd ${path_to_socket_server}
mkdir build
```

Then build the application:

```
cd build
cmake ..
make
```
(If errors occured here, you may need to modify the cmake files in ```contrib-2.1.0/ports/unix/Filelists.cmake``` and ```contrib-2.1.0/ports/unix/socket_server/CMakeList.txt```)
After that, use command to run:

```
./socket_server
```

Also, it takes the same procedures to compile and run the client in ```/ports/unix/socket_client/```.
Do not forget to change the ip/gateway/netmask to what you want in ```socket_server.c``` and ```socket_client.c```. 