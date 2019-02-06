#! /bin/sh

make 
sudo insmod part2/part2.ko
./procAncestry $1
sudo rmmod part2/part2.ko
