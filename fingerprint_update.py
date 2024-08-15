import concurrent.futures
import subprocess,json

import sys
sys.path.append('/opt/asset_scan')

from lib.common import WEBANALYZE_PATH,OBSERVER_PATH

def webanalyze_update():
    nmap_path = WEBANALYZE_PATH
    nmap_cmd = [nmap_path, "-update"]
    result=subprocess.run(nmap_cmd, check=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(result)


def observer_ward_update():
    nmap_path = OBSERVER_PATH
    nmap_cmd = [nmap_path, "-u"]
    result=subprocess.run(nmap_cmd, check=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(result)

def update():
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        futures.append(executor.submit(observer_ward_update))
        futures.append(executor.submit(webanalyze_update))
        concurrent.futures.wait(futures)

if __name__ == '__main__':
    update()


