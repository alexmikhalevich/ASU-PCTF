#!/usr/bin/env python3
import requests
import json
import os
import time
import subprocess
import swpag_client

def attack(host):
        out = subprocess.run(['./attack.sh', host], stdout=subprocess.PIPE)
        #print(out.stdout.decode('utf-8'))
        strOut = out.stdout.decode('utf-8')
        strStart = out.stdout.decode('utf-8').find('FLG')
        newStr = strOut[strStart:]
        strEnd = newStr.find('\n')
        return newStr[:strEnd]


def getLiveHosts():
    response = requests.get('http://52.8.181.219/api/game/state').json()
    teams = response['static']['teams']
    myTeams = []
    for k,v in teams.items():
       myTeams.append("team"+k)
    return myTeams

def submitFlag(flag):
    t = swpag_client.Team('http://52.52.83.248', 'hIGoCfCsFD8HGyeUJK1q')
    print(t.submit_flag([flag]))

def attackAll():
    teams = getLiveHosts()
    flags = []
    for i in teams:
        print(attack(i))
        flags.append(attack(i).strip())
        submitFlag(attack(i).strip())
    print(flags)


start = 1
while True:
    response = requests.get('http://52.8.181.219/api/game/state').json()
    dynamic = response["dynamic"]
    current = int(dynamic[0]["tick"]["tick_id"])
    if current > start:
        print("atatck")
        attackAll()
        time.sleep
        print(start, current)
        start = current
    else:
        print("sleep")
        print(current, start)
        time.sleep(5)

