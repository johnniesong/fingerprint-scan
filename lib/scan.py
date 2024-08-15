import subprocess
import argparse
import re,random
import json
from collections import defaultdict
import concurrent.futures
from lib.read_nmap_scan_result import read_nmap_scan_result
from config import MASSCAN_PATH,NMAP_PATH,NMAP_USE_CACHE,MASSCAN_USE_CACHE
from lib.common import save_obj_to_file,load_obj_from_file

def is_valid_ip(ip):
    # Regular expression to match IP address format
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    return bool(ip_pattern.match(ip))

def parse_masscan_output(masscan_output):
    results = json.loads(masscan_output)

    # 使用 defaultdict 创建一个以 IP 为键的字典，值是该 IP 对应的端口列表
    ip_ports_mapping = defaultdict(list)

    for result in results:
        ip = result.get("ip", "")
        ports = result.get("ports", [])

        # 添加到字典中
        ip_ports_mapping[ip].extend([str(port_info["port"]) for port_info in ports])

    return ip_ports_mapping

def nmap_scan(ip, ports):
    nmap_path=NMAP_PATH
    #random_num=random.randint(9000000000,10000000000)
    output_file_path="./nmap_scan_output_"+ip+".xml"
    print(output_file_path)
    ports_str = ",".join(ports)
    nmap_cmd = [nmap_path, ip, "-p", ports_str, "-sV", "-Pn", "-oX", output_file_path]
    subprocess.run(nmap_cmd, check=True)

    # 读取 nmap 输出文件
    with open(output_file_path, 'r') as f:
        nmap_output = f.read()

    result=read_nmap_scan_result(nmap_output)
    return result

def filter_result_by_open_port_num(ip_ports_mapping):
    new_result={}
    for k,v in ip_ports_mapping.items():
        if k=="default_factory":
            continue
        if len(v)>100:
            new_result.update({k: []})
            if "80" in v:
                new_result[k].append("80")
            if "443" in v:
                new_result[k].append("443")
        else:
            new_result.update({k:v})
    return new_result


def run_masscan_and_nmap(output_file_path, target, ports, rate):
    masscan_path = MASSCAN_PATH  # 替换为实际的 masscan 路径，再替换下面 is_valid_ip(target) 判断中 "masscan"

    # 根据输入参数类型构建 masscan 命令
    if is_valid_ip(target):
        masscan_cmd = [masscan_path, target, "--ports", ports, "-oJ", output_file_path, "--rate", rate]
    else:
        masscan_cmd = [masscan_path, "-iL", target, "--ports", ports, "-oJ", output_file_path, "--rate", rate]

    total_result={}
    try:
        if MASSCAN_USE_CACHE==True:
            ip_ports_mapping=load_obj_from_file("./cache/masscan_scan_result.json")
        else:
            # 调用 masscan 命令
            subprocess.run(masscan_cmd, check=True)
            print("Masscan completed successfully.")

            # 读取 masscan 输出文件
            with open(output_file_path, 'r') as f:
                masscan_output = f.read()

            if len(masscan_output) <= 0:
                print("Masscan output is empty.")
                return {}

            # 解析 masscan 输出
            # {'ip': '47.95.53.8', 'timestamp': '1701420595', 'ports': [{'port': 80, 'proto': 'tcp', 'status': 'open', 'reason': 'syn-ack', 'ttl': 56}]}
            ip_ports_mapping = parse_masscan_output(masscan_output)
            ip_ports_mapping = filter_result_by_open_port_num(ip_ports_mapping)

            save_obj_to_file(ip_ports_mapping, "./cache/masscan_scan_result.json")

        if NMAP_USE_CACHE==True:
            total_result=load_obj_from_file("./cache/nmap_scan_result.json")
        else:
            max_workers = 10
            # 使用多线程扫描每个 IP 的端口
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # 提交每个 IP 的扫描任务
                futures = [executor.submit(nmap_scan, ip, ports) for ip, ports in ip_ports_mapping.items()]

                for future in futures:
                    result = future.result()
                    total_result.update(result)

                # # 等待所有任务完成
                # concurrent.futures.wait(futures)

            save_obj_to_file(total_result, "./cache/nmap_scan_result.json")

        print("Scan completed successfully.!!!!!!!!!!!!!!!!!!!!!!!")
        for k,v in total_result.items():
            print(k,v)

        return total_result

    except subprocess.CalledProcessError as e:
        print(f"Error running Masscan: {e}")

if __name__ == "__main__":
    # parser = argparse.ArgumentParser(description="Run Masscan with custom parameters")
    # parser.add_argument("-i", "--ip", dest="target", help="Single target IP address")
    # parser.add_argument("-f", "--file", dest="target", help="File containing target IPs (one per line)")
    # parser.add_argument("-o", "--output", dest="output_file_path", default="./output.txt", help="Output file path,default output.txt")
    # parser.add_argument("-r", "--rate", dest="rate", default="1000", help="Scan rate,dafault 1000")
    # parser.add_argument("-p", "--ports", dest="ports", default="1-65535", help="Port range (default: 1-65535)")
    #
    # args = parser.parse_args()
    #
    # if not args.target:
    #     print("Please specify either -i/--ip or -f/--file for target IPs.")
    #     exit(1)
    #
    # # 调用 run_masscan 函数
    output_file_path="./output.txt"
    target="../../file.txt"
    ports="1-65535"
    rate="3000"
    run_masscan_and_nmap(output_file_path, target, ports, rate)