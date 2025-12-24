# Wirepath Switch (WPS)


## Key Features


## Quick Start

### Build Instructions

### Self Test 

### Running WPR

### Environment Configuration 
A number of Linux command line arguments are suggested for optimal operation of the WPS subsystem, the sequence below was used for all testing during WPS development: 

```text 
GRUB_CMDLINE_LINUX="intel_iommu=on iommu=pt pcie_aspm=off pcie_port_pm=off isolcpus=nohz,domain,managed_irq,<MIN_CPU>-<MAX_CPU> nohz_full=<MIN_CPU>-<MAX_CPU> rcu_nocbs=<MIN_CPU>-<MAX_CPU>"
```

#### DMA/IOMMU Behavior 
- intel_iommu=on - forces Intel VT-d to be enabled. This is required for use of vfio-pci drivers which is how DPDK gets control over NIC interfaces 
- iommu=pt - Enables IOMMU but puts most devices in a 1:1 identity mapping, this reduces the IOMMU TLB translation overhead. We are also not running a true virtualized env so not needed. 

#### PCIe Power Management 
- pcie_aspm=off pcie_port_pm=off: Some NIC's don't have great support for PCIe ASPM, this disables it so we don't hit weird issues when unbinding and re-binding NIC drivers. 

#### Core Isolation 
Note, while not required, it's strongly suggested to isolate all cores you plan to launch WPS and any WPS secondary processing applications on. Adjust the <MIN_CPU>-<MAX_CPU> to be the range or list of physical core ID's you plan to run on. Note, do not include core 0 on this, we expect that core 0 is always a shared core, no need to isolate it. 

- isolcpus=nohz,domain,managed_irq,<MIN_CPU>-<MAX_CPU> - This command string basically tells linux "these cores are special, don't mess with them": 
    - nohz - avoids schduling periodic timer tickets on these CPUs 
    - domain - prevents load-balancer (CFS Domain) from putting tasks onto these CPUs
    - managed_irq - prevents linux for assigning managed interrupts (e.g. MSI-X) on these CPUs. Note DPDK runs poll mode drivers (PMD) so we explicitly do not want interrupts landing
                    on our cores.

- nohz_full=<MIN_CPU>-<MAX_CPU> - Enables full dynticks mode that complete removes periodic scheduler tickets on these cores. Kernel only runs when a syscall is made or an interrupt fires. 
    - prevents 1ms timer interrupts
    - removes jitter at high PPS rates

- rcu_nocbs=<MIN_CPU>-<MAX_CPU> - Prevents RCU callbacks from executing on the specified CPU cores, moves them all to other coress. 
    -RCU callbacks can interrupt dataplane loops, cause long latency spikes.


## Architecture & Design
📘 See [Design Readme](docs/design/README.md)

## Documentation
- Design Documents: docs/design/
- Architecture Diagrams: docs/architecture/
- Diagram Sources: docs/diagrams/

## Repo Structure (Summary)
```text
.
├── configs             - System configuration file examples
├── docs                - Project Documentation
│   ├── architecture    - Build file & artifact template for md images
│   ├── design          - Design documents 
│   └── diagrams        - Mermaid source diagram files
├── include             - Application C header files
├── pcaps               - Example pcaps for testing 
├── python              - Python utilities for interfacing with WPR Control Interface
├── src                 - Application C source files
├── test                - Unit Tests
│   └── common          - Common unit test support functions
├── tools               - Useful bash scripts for initializing systems, building WPR, running WPR, etc.
└── traffic_configs     - Example config files for loading traffic templates for replay


```
## Status
Experimental / Active development
