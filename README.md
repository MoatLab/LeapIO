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
  |- driver/pnvme.c                # Standalone NVMe representations
  |- driver/rdma/                  # Kernel-level RDMA test driver
  |- driver/wpt-qpmap.c            # LeapIO Queue Pair abstractions
  |- driver/oct-core.c             # Kernel-level OpenChannel-SSD test driver
  |- driver/ats.c                  # LeapIO address translation service
  |- driver/wpt-dbg.c              # Debugging utilities
  |- driver/wpt-core.c             # LeapIO host driver main
  |- driver/rdma.c                 # Kernel-level RDMA utilities
  |- driver/wpt-util.c             # LeapIO host driver utilies
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

