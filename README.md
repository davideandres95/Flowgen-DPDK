# Flowgen - A simpe flow generator powered by DPDK
This application generates a "configurable" number of flows. It is primary intended to test the behaviour of a Mellanox 
ConnectX-5 with the DPDK library.

Using a single core, it generates 34.59Mpps. 
Tested on an AMD EPYC 7402P 24-Core Processor running at 2.8GHz, with 128GB of RAM, and QSFP28 interfaces.
Check the _Setup Information_ section for more information.

## How to compile
Compilation is based on Cmake. Adapt your folders and CPU number accordingly
```sh
cmake -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" -S ./ -B ./buildDir
cmake --build ./buildDir --target flowgen_dpdk -- -j 14
```
## How to run
Assuming that the PCI address of the NIC to be used is `c4:00.2`:
```sh
./flowgen_dpdk -l 2 -n 1 --file-prefix pg_flowgen -a c4:00.2 --huge-dir /mnt/huge
```
## How to configure
At the moment, parameters such as MAC, IP and port ranges are hardcoded in the `main.c` file.

## Setup Information
```sh
$ ./cpu_layout.py 
======================================================================
Core and Socket Information (as reported by '/sys/devices/system/cpu')
======================================================================

cores =  [0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 16, 17, 18, 20, 21, 22, 24, 25, 26, 28, 29, 30]
sockets =  [0]

        Socket 0       
        --------       
Core 0  [0, 24]        
Core 1  [1, 25]        
Core 2  [2, 26]        
Core 4  [3, 27]        
Core 5  [4, 28]        
Core 6  [5, 29]        
Core 8  [6, 30]        
Core 9  [7, 31]        
Core 10 [8, 32]        
Core 12 [9, 33]        
Core 13 [10, 34]       
Core 14 [11, 35]       
Core 16 [12, 36]       
Core 17 [13, 37]       
Core 18 [14, 38]       
Core 20 [15, 39]       
Core 21 [16, 40]       
Core 22 [17, 41]       
Core 24 [18, 42]       
Core 25 [19, 43]       
Core 26 [20, 44]       
Core 28 [21, 45]       
Core 29 [22, 46]       
Core 30 [23, 47]       
```

```sh
$ dpdk-hugepages.py -s
Node Pages Size Total
0    8     1Gb    8Gb

Hugepages mounted on /mnt/huge /dev/hugepages
```