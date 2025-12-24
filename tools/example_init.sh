#!/bin/bash 

#load vfio driver 
modprobe vfio-pci 

#bind PCI devices to vfio-pci driver

#reserve 1G hugepage 
./tools/make_hugepagefs.sh 8

echo "Initialization complete."