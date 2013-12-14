#!/bin/bash

if uname | grep MINGW
then
net stop vmmr0
net start vmmr0
exit
fi


if lsmod|grep vmmr0
then
sudo rmmod  vmmr0
fi
sudo insmod ./x86/vmmr0.ko

sudo chmod 777 /dev/vmmr0
