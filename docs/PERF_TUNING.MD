Copyright (c) 2017 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Tips for enabling coremask
==========================

Consider example output of 'lcpu' on a Haswell system:
# lscpu -a -e=socket,cpu,core
SOCKET CPU CORE
0      0   0
0      1   1
0      2   2
0      3   3
0      4   4
0      5   5
0      6   6
0      7   7
0      8   8
0      9   9
1      10  10
1      11  11
1      12  12
1      13  13
1      14  14
1      15  15
1      16  16
1      17  17
1      18  18
1      19  19
0      20  0
0      21  1
0      22  2
0      23  3
0      24  4
0      25  5
0      26  6
0      27  7
0      28  8
0      29  9
1      30  10
1      31  11
1      32  12
1      33  13
1      34  14
1      35  15
1      36  16
1      37  17
1      38  18
1      39  19

1. The s1u and sgi core should be on the same socket as the NIC device for better performance.
Check "/sys/bus/pci/devices/" + pci + "/numa_node" and enable core on that socket.
Eg, cat /sys/bus/pci/devices/0000\:86\:00.0/numa_node gives '1'
So, s1u core should be on socket 1.
So, enable core mask as: 0x100000

2. For better performance run all the workers on the same socket as NIC, enable core mask such that all the cores lie on the same socket.
The cores corresponding to each socket can be found out using lscpu.
In this example, to enable 5 cores on socket 0, the core mask should be 0x1f
Similarly to enable 5 cores on socket 1, the core mask should be 0x7c00

3. To enable hyperthreading, it should be enabled in BIOS during boot.
Confirm if hyperthreading is enabled or not by checking the output of 'lscpu'
Check "Thread(s) per core:    2"

Since hyperthreading is enabled in the above system, CPUs 20-29 are the second threads for 0-9 CPUs.
If hyperthreading is enabled, to run 1 core/ 2threads configuration, enable the sibling core
of the same physical core by enabling it through the core mask.
In the above example, 0x1f0001f should be used to enable 5 physical cores with 2 threads each.

4. Once the application is running, monitor the performance of the cores using 'top -H'
Press 'f', bring cursor down to ' P       = Last Used Cpu (SMP)', press spacebar and then press ESC
This will show the CPU used for the process.
1. If the system is HT enabled and only one thread per core is being used, monitor
the load on the sibling core as well. Sometimes, kernel takes up that CPU for interrupts.
This can be avoided by putting all the desired cores in isolcpus.
Add 'isolcpus=0-9,20-29' in kernel commandline parameter to isolate all socket 0 cores in above example.

5. Sometimes timer interrupts are received on core 0, even if it is added in isolcpus.
Observe this in 'top -H' for the %CPU. Normally, the ngic application will completely (100%) use the core
on which it is running. But due to some kernel glitches, sometimes, it can be observed that core 0's
usage by ngic app may go to a little lower value like 97%. 
So, in such case, it is always better to avoid this core for application purpose.
This can be done by not enabling this core (in this example core 0) in the coremask.
If such glitch is observed, avoid enabling that in coremask for the application usage.

6. If cores number are sliced up for example 'lscpu -a -e=socket,cpu'
SOCKET CPU
0      0
1      1
0      2
1      3
0      4
1      5
0      6
1      7
0      8
1      9
0      10
1      11
0      12
1      13
0      14
1      15
0      16
1      17
0      18
1      19
0      20
1      21
0      22
1      23
0      24
1      25
0      26
1      27
0      28
1      29
0      30
1      31
0      32
1      33
0      34
1      35
0      36
1      37
0      38
1      39

In such case, to enable 5 cores for s1u, sgi, iface, stats and loadbalancer on socket 0, mask should be 0x55
And then to enable 2 worker cores, 0x1555
