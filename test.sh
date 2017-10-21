#!/bin/bash

make
#sudo rmmod latprof
sudo insmod latprof.ko
dmesg
#sudo insmod latprof.ko int_param=12 int_str='"0 425 6 69 600 800 404 123 321 1000 12 231"'
#dmesg > temp.log
#tail -35 temp.log
