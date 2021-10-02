```

    __                     ________ 
   / /   ___  ____ _____  /  _/ __ \
  / /   / _ \/ __ `/ __ \ / // / / /
 / /___/  __/ /_/ / /_/ // // /_/ / 
/_____/\___/\__,_/ .___/___/\____/     -- Efficient and Portable Virtual NVMe Storage on ARM SoCs 
                /_/                 

```

Ok, code is being incrementally released, please stay tuned! You can fill in this [request form](https://docs.google.com/forms/d/e/1FAIpQLSeg-NpQ8hBlZGTgKVt72vOTo6HHYi9DX1_3DmioP2zTbe3cqw/viewform?vc=0&c=0&w=1&flr=0) to get notified when the entire code repo is ready. 

Feel free to contact Huaicheng Li (hcli@cmu.edu) for any questions.

Consider citing LeapIO using the following bib entry if you find our paper useful:

```
@InProceedings{li2020leapio,
  author = {Li, Huaicheng and Hao, Mingzhe and Novakovic, Stanko and Gogte, Vaibhav and Govindan, Sriram and Ports, Dan and Zhang, Irene and Bianchini, Ricardo and Gunawi, Haryadi S. and Badam, Anirudh},
  title = {LeapIO: Efficient and Portable Virtual NVMe Storage on ARM SoCs},
  booktitle = {Proceedings on the International Conference on Architectural Support for Programming Languages and Operating Systems (ASPLOS)},
  year = {2020},
  month = {March},
  url = {https://dl.acm.org/doi/10.1145/3373376.3378531},
}
```

Thanks for checking this!


### LeapIO code structure

1. LeapIO Host OS/Kernel (Modified Linux)

```
Linux
  |- drivers/nvme/host/lightnvm.c  # LeapIO support for OpenChannel-SSD
  |- drivers/nvme/host/core.c      # NVMe driver extensions for LeapIO
  |- drivers/nvme/host/pci.c       # NVMe driver extensions for LeapIO
  |- drivers/vfio/vfio.c           # VFIO ``noiommu`` mode hacks
  |- mm/leap-mm.c                  # LeapIO page table management utilities
```

2. LeapIO Host Driver

```
Driver - LeapIO modular/standalone driver for Linux
  |- pnvme.c                # Standalone NVMe representations
  |- rdma/                  # Kernel-level RDMA test driver
  |- wpt-qpmap.c            # LeapIO Queue Pair abstractions
  |- oct-core.c             # Kernel-level OpenChannel-SSD test driver
  |- ats.c                  # LeapIO address translation service
  |- wpt-dbg.c              # Debugging utilities
  |- wpt-core.c             # LeapIO host driver main
  |- rdma.c                 # Kernel-level RDMA utilities
  |- wpt-util.c             # LeapIO host driver utilies
```

3. LeapIO Hypervisor (Modified QEMU/FEMU)

```
FEMU - (used to start user VMs as well as emulating ARM-SoC)
  |- backends/hostmem-file.c       # -+
  |- hw/i386/pc.c                  #  +--- LeapIO hacks to map the entire host address space to the SoC-like VM
  |- backends/hostmem.c            # -+
  |- util/leap-util.c              # LeapIO utilities for NVMe Queue Pair mapping to SoC
  |- hw/misc/ivshmem.c             # The veapIO BAR exposed to the SoC
  |- hw/block/leap-nvme.c          # -+
  |- hw/block/nvme.c               #  +--- LeapIO shim layers between VM virtual NVMe drive and the Host physical NVMe drive
  |- hw/block/femu/femu-oc.c       # -+
```

4. LeapIO Runtime

```
Runtime - (run on the SoC)
  |- pagemap.c                     # /proc/pid based address translation utilities
  |- rdma-leap.c                   # RDMA utilities for NVMe-over-RDMA
  |- rdma-pcie.c                   # RDMA-over-PCIe utilities for x86-SoC communication
  |- tests/                        # Various test cases for LeapIO
  |- svk.c                         # ARM-SoC specific utilities
  |- tcp.c                         # TCP utilities for NVMe-over-TCP
  |- dmabuf.c                      # DMA utilities
  |- socp.c                        # The giant LeapIO runtime (main entry)
```

### Prerequiste


- Server: A server with >16GB DRAM, >8cores, an NVMe SSD 
- Broadcom StingRay SVK Board or a specialized VM plus a RDMA NIC (more details below)


### Build LeapIO Components (Host kernel, driver, runtime and FEMU)

(1). Compile host kernel


    $ cp vSSD/conf/quantumleap-host-kernel-config vSSD/linux/.config
    $ cd vSSD/linux
    $ sudo make -j16 # change 16 to # of cores in your machine for best performance
    $ sudo make modules_install
    $ sudo make install
    $ sudo update-grub2

Configure host grub file to boot newly compiled host kernel

    $ sudo mv /etc/default/grub /etc/default/grub.bak
    $ sudo cp vSSD/conf/host-etc-default-grub /etc/default/grub

Doule check the line starting with ``GRUB_CMDLINE_LINUX`` contains the following options in ``/etc/default/grub``:

    GRUB_CMDLINE_LINUX="intel_iommu=off transparent_hugepage=never modprobe.blacklist=nvme,nvme_core"


    $ sudo update-grub2

    # reboot the machine, make sure we enter the Leap kernel
    $ sudo reboot

    # Login again after the host is up
    $ uname -a  # should give output containing "4.15.0-rc4-Leap"


Note this step is necessary for successfully building LeapIO Driver in the next
step.


    # Verify the SSD
    sudo modprobe nvme
    sudo nvme list
    sudo nvme id-ctrl /dev/nvm0n1  | grep -i mdts


(2). Compile LeapIO WPT kernel module

    $ cd Driver
    $ make
    # there should be a kernel module named “wpt.ko” generated, we will load it later
    # ls wpt.ko


(3). Compile FEMU

Note: please change ``bs_size`` in ``hw/block/nvme.c`` to make it same as the value you get from ``sudo blockdev --getsz64 /dev/nvme0n1``

    $ cd FEMU/build-femu
    # install dependencies for FEMU
    $ cp ../femu-scripts/pkgdep.sh .
    $ sudo ./pkgdep.sh

    # do FEMU compilation
    $ cp ../femu-scripts/femu-compile.sh .
    $ ./femu-compile.sh

    The FEMU binary will appear as "x86_64-softmmu/qemu-system-x86_64"
    $ ls x86_64-softmmu/qemu-system-x86_64


(4). Prepare VM images to serve as the user VM and the emulated SoC (referred to as "SoC-VM", it is needed when Broadcom SVK SoC is not available):


    # Download Ubuntu 16.04 server ISO file
    $ wget http://releases.ubuntu.com/16.04/ubuntu-16.04.5-server-amd64.iso
    $ sudo apt-get install qemu-system-x86
    $ qemu-img create -f qcow2 socvm.qcow2 20G

    # install guest OS using system QEMU
    $ qemu-system-x86_64 -cdrom /path/to/ubuntu-16.04.5-server-amd64.iso -hda socvm.qcow2 -boot d -net nic -net user -m 4096 -localtime -smp 4 -cpu host -enable-kvm

    # After installation is done, boot it with system QEMU and do some configurations IN SOCVM
    $ sudo cp /etc/default/grub /etc/default/grub.original
    $ cp /home/huaicheng/git/quantumleap-public/vSSD/conf/socvm-grub/socvm-grub /etc/default/grub
    $ sudo update-grub2
    $ sudo shutdown -h now 

    # Now, socvm.qcow2 is ready to be used with FEMU 


(5). Compile LeapIO runtime (note this step needs to be done inside the VMs, refer back to it later after the VMs are up)


Inside SoC-VM, we need to run ``socp``, first scp it from vSSD/soc-prog into SoC-VM if not, then

    vm$ cd runtime
    vm$ make # the generated binary is "socp"


### Run LeapIO

- On the host side, open a separate terminal to observe kernel log outputs, and do the following:

    $ sudo mknod /dev/wpt c 200 0
    $ sudo modprobe nvme
    $ cd vSSD/one
    $ sudo insmod wpt.ko


    # configure bridge rule to allow traffic through “fbr0”, needs to be done once 
    $ sudo touch /usr/local/etc/qemu/bridge.conf
    $ echo "allow fbr0" | sudo tee /usr/local/etc/qemu/bridge.conf


- Boot SoC-VM:


    $ cd FEMU/build-femu
    $ sudo ./socvm.sh


Login to SoC-VM via ssh:

    $ ssh -p8089 user@localhost


Once you're inside the socvm,


    socvm$ lspci | grep Inter-VM | awk '{print $1}'  # this give you the correct ID, modify 84 & 85 accordingly 


Then, copy ``Runtime/`` to the SoC-VM and compile socp again and run it


    socvm$ make
    socvm$ sudo ./socp # Keep it running in the background


- Boot user VM (Referred to as ``DBVM``)

On host machine, do

    $ cd FEMU/build-femu
    $ sudo ./dbvm.sh
    # Login to DBVM:
    $ ssh -p8080 user@localhost


Inside DBVM:

    dbvm$ sudo modprobe nvme
    # Load pblk module if using OCSSD
    dbvm$ sudo modprobe pblk

    # if successful, we should have a nvme device seen by dbvm now
    dbvm$ sudo nvme list

    # we can run benchmark over the device

    # first, modify t.fio filename option to use "filename=/dev/nvme0n1"
    dbvm$ sudo fio t.fio

