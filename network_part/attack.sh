#!/usr/bin/expect -f
set target [lindex $argv 0];
set timeout 2
spawn nc $target 10001
expect "Enter username:\r"
send -- "someid\r"
expect "Enter password:\r"
send -- "totallyrandomtoken\r"
expect "Enter title of work:\r"
send -- "test\r"
expect "<S>olve eqns or <R>etrieve result\r"
send -- "R\r"
expect "FLG"

send -- "\r\r"
send -- "\r\r"
