#!/bin/bash

#targets = $(cat /etc/hosts | grep -o 'team.*')
for i in $(cat /tmp/liveHosts)
do
echo $i
./attack.sh $i
done
