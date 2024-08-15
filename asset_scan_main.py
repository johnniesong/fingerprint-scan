import json,hashlib,os
from lib.tools import Time
from lib.scan import run_masscan_and_nmap
from lib.fingerprint import FingerPrint
from lib.common import save_obj_to_file,load_obj_from_file,is_ip_address
import pebble
from lib.common import resolve_hostnames

class Asset_scan:
    def __init__(self,env,is_test,use_cache):
        self.env = env
        self.is_test = is_test
        self.use_cache = use_cache
        pass


    def build_targets(self,targets):
        new_targets={}
        for item in targets:
            if is_ip_address(item):
                new_targets.update({item:{'type':'eip','domain_list':[]}})
            else:
                domain_ip_map = resolve_hostnames([item])
                for domain, ip in domain_ip_map.items():
                    if len(ip) > 0:
                        if ip not in targets:
                            new_targets.update({ip: {"type": "domain", "domain_list": [domain]}})
                        else:
                            new_targets[ip]['domain_list'].append(domain)
        return new_targets

    def scan_targets(self,targets):
        output_file_path = "./output.txt"
        target_file_path = "targets.txt"
        ports = "1-65535"
        rate = "4000"

        targets_list=[]
        for target,data in targets.items():
            targets_list.append(target)

        with open(target_file_path,'w') as file:
            file.write("\n".join(targets_list))

        result=run_masscan_and_nmap(output_file_path, target_file_path, ports, rate)

        return result

    def ip_conver_to_domain_before_fingerprint(self,targets,nmap_result):
        new_result={}
        for ip,data in targets.items():
            if len(data['domain_list'])>0:
                for domain in data['domain_list']:
                    asset_value=domain
                    tmp_nmap_result=nmap_result.get(ip,[])
                    data.update({"nmap_result":tmp_nmap_result})
                    new_result.update({asset_value:data})
            else:
                tmp_nmap_result = nmap_result.get(ip, [])
                data.update({"nmap_result": tmp_nmap_result})
                new_result.update({ip:data})

        return new_result

    def identify_targets_worker(self,target,data):
        fingerPrint = FingerPrint()
        ip = target
        tmp_result = []
        nmap_scan_result = data['nmap_result']
        for item in nmap_scan_result:
            port = item['port']
            state = item['state']
            service = item['service']
            version = item['version']
            identify_result = fingerPrint.start(ip, port)
            tmp_result.append({
                "port": port,
                "state": state,
                "service": service,
                "service_version": version,
                "identify_result": identify_result
            })

        # for k,v in targets.items():
        #     print(k)
        #     print(v)
        result = data.copy()
        result["identify_result"] = tmp_result
        return target,result


    def identify_targets_v2(self,targets):
        final_results = {}
        # 使用 ThreadPoolExecutor 来创建线程池
        with pebble.ProcessPool(max_workers=8) as executor:
            # 提交任务到线程池
            for target, data in targets.items():
                future = executor.schedule(self.identify_targets_worker, args=[target,data],timeout=300)

                try:
                    future_result= future.result()
                    final_results[future_result[0]] = future_result[1]
                except Exception as error:
                    if error.__class__.__name__ == 'TimeoutError':
                        print("111111111111111111111111111111111111111111111111111")
                        print("unstable_function took longer than %d seconds" % error.args[1])
                        print(target)
                        print(data)
                        data.update({"identify_result":[]})
                        final_results[target] = data
                    print("unstable_function raised %s" % error)
                    print(error)  # Python's traceback of remote process


        return final_results


    def print_data(self,data):
        atime=Time().now()
        env=self.env
        for ip, items in data.items():
            asset_value=ip
            asset_type=items['type']
            identify_result=items.get('identify_result', [])
            for item in identify_result:
                port = item['port']
                state = item['state']
                service = item['service']
                service_version = item.get('service_version', '')
                for identify in item.get('identify_result', []):
                    fingerprint_app_name = identify.get('app_name', '')
                    fingerprint_match_string = identify.get('match_string', '')
                    fingerprint_source = identify.get('source', '')
                    fingerprint_target_path = identify.get('path', '')
                    fingerprint_app_version=""

                    if isinstance(fingerprint_match_string,list):
                        fingerprint_match_string=','.join(fingerprint_match_string)
                    else:
                        fingerprint_match_string=str(fingerprint_match_string)

                    unique_string = str(asset_value) + str(port) + str(fingerprint_app_name) + fingerprint_match_string + str(fingerprint_source) + str(fingerprint_target_path) + str(fingerprint_app_version)
                    # 生成 MD5 哈希
                    id = hashlib.md5(unique_string.encode('utf-8')).hexdigest()
                    # 插入数据库
                    query = (
                        "REPLACE INTO asset_scan_result (id,asset_value,asset_type,env,atime, port, state, service,service_version, fingerprint_app_version, fingerprint_app_name, fingerprint_match_string, fingerprint_source, fingerprint_target_path) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                    )
                    values = (id,asset_value,asset_type,env,atime, port, state, service,service_version, fingerprint_app_version, fingerprint_app_name, fingerprint_match_string, fingerprint_source, fingerprint_target_path)
                    print(values)


    def start(self,targets):
        if self.use_cache==False:
            scan_result=self.scan_targets(targets)
            save_obj_to_file(scan_result,os.path.join(os.path.dirname(os.path.abspath(__file__)))+"/cache/scan_result.result")
        else:
            scan_result=load_obj_from_file(os.path.join(os.path.dirname(os.path.abspath(__file__)))+"/cache/scan_result.result")

        print("scan_targets finish!!!!!!!!!!!!!!!!!!!!!!")
        targets_scan_result=self.ip_conver_to_domain_before_fingerprint(targets,scan_result)

        if self.use_cache==False:
            scan_and_identify_result=self.identify_targets_v2(targets_scan_result)
            save_obj_to_file(scan_and_identify_result,os.path.join(os.path.dirname(os.path.abspath(__file__)))+"/cache/scan_and_identify_result.result")
        else:
            scan_and_identify_result=load_obj_from_file(os.path.join(os.path.dirname(os.path.abspath(__file__)))+"/cache/scan_and_identify_result.result")
        print("scan_and_identify finish!!!!!!!!!!!!!!!!!!!!!!")

        #输出最终扫描结果
        self.print_data(scan_and_identify_result)


if __name__ == '__main__':
    env = 'pro'#仅标识数据属于哪个环境,无特殊用途
    asset_scan = Asset_scan(env,is_test=False,use_cache=False)
    targets=["1.1.1.1","www.baidu.com"]#仅能填写ip或域名
    new_targets=asset_scan.build_targets(targets)
    asset_scan.start(new_targets)

