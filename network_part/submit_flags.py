#!/usr/bin/env python3
import swpag_client
with open("./results") as f:
    flags = f.readlines()
for i in flags:
    print(i)
    t = swpag_client.Team('http://52.52.83.248', 'hIGoCfCsFD8HGyeUJK1q')
    print(t.submit_flag([str(i).strip()]))
