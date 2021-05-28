#!/bin/bash
#
# Download VM
# 
# https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/
mkdir work
cd work
wget https://aka.ms/windev_VM_virtualbox
mv windev_VM_virtualbox windev_VM_virtualbox.zip
unzip windev_VM_virtualbox.zip
vboxmanage import --vsys 0 --unit 12 --disk ./VIKING-MALDEV-disk001.vmdk --vmname VIKING-MALDEV --cpus 2 --memory 8192 WinDev2104Eval.ova
VBoxManage startvm VIKING-WIN10DEV
rm windev_VM_virtualbox.zip
