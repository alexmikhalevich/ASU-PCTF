
import requests
import json
import os

response = requests.get('http://52.8.181.219/api/game/state').json()


dynamic = response["dynamic"]
service_states = dynamic[0]["service_states"]["5"]

for i in range(len(service_states)):
    if (service_states[str(i+1)]["service_state"]) != "up":
        os.system("sudo pkill -f Defense.py")
        print("Defense.py terminated")