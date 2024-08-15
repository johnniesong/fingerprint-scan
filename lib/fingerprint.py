import concurrent
import os
import subprocess,json
from lib.common import WEBANALYZE_PATH,DISMAP_PATH,OBSERVER_PATH
from lib.common import is_ip_address,add_source_to_result,add_path_to_result
from fingerprint_custom import Fingerprint_custom
from config import *

class FingerPrint:
    def __init__(self):
        pass


    def webanalyze_scan(self,target):
        nmap_path = WEBANALYZE_PATH
        nmap_cmd = [nmap_path, "-host", target, "--crawl", "3", "--output","json","-silent"]
        result=subprocess.run(nmap_cmd, check=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        webanalyze_output = result.stdout
        result = self.read_webanalyze_scan_result(webanalyze_output)
        result = add_source_to_result(result, "webanalyze")
        result = add_path_to_result(result, target)

        return result

    def read_webanalyze_scan_result(self,nmap_output):
        result= []
        # 解析 JSON 字符串
        try:
            data = json.loads(nmap_output)

            # 检查 'matches' 中的每个元素
            for match in data.get('matches', []):  # 使用 get 方法来避免 KeyError
                # 检查是否有 'app_name' 字段
                app_name = match.get('app_name')  # 使用 get 方法提取 app_name，如果不存在则返回 None
                match_string_list = match.get('matches',[])  # 使用 get 方法提取 app_name，如果不存在则返回 None
                match_string=str(match_string_list)
                if app_name is not None:
                    if len(app_name)>1:
                        result.append({"app_name":app_name,"match_string":match_string})
        except:
            pass
        return result


    #./dismap-0.4-linux-amd64 -u http://1.1.55.131:9000 -j output.txt
    def dismap_scan(self,ip,port):
        nmap_path = DISMAP_PATH
        output_file_path = "./dismap_scan_output_" + ip.replace(":","_").replace("//","_") + "_" + str(port) + ".xml"
        if is_ip_address(ip):
            nmap_cmd = [nmap_path, "-i", ip,"-p" , str(port), "-j", output_file_path,"--np","--nc"]
        else:
            nmap_cmd = [nmap_path, "-u", ip, "-j", output_file_path,"--np","--nc"]
        subprocess.run(nmap_cmd, check=True)

        with open(output_file_path, 'r') as f:
            nmap_output = f.read()

        os.remove(output_file_path)

        result = self.read_dismap_scan_result(nmap_output)
        result=add_source_to_result(result,"dismap")
        if port!=None:
            result = add_path_to_result(result, ip+":"+str(port))
        else:
            result = add_path_to_result(result, ip)
        return result


    def read_dismap_scan_result(self,output):
        result=[]
        try:
            # 解析 JSON 字符串
            data = json.loads(output)

            # 尝试获取'banner.string'字段
            banner_string = data.get('banner.string', None)
            identify_string = data.get('identify.string', "")

            # 检查'banner.string'是否存在
            if banner_string is not None and len(banner_string)>1:
                result.append({"app_name":banner_string,"match_string":identify_string})
        except:
            pass

        return result


    def ob_official_scan(self,ip,port):
        port=str(port)
        bin_path = OBSERVER_PATH
        output_file_path = "./ob_official_output_" + ip.replace(":","_").replace("//","_") + "_" + port + ".xml"
        bin_cmd = [bin_path, "-t", ip, "-j", output_file_path]
        subprocess.run(bin_cmd, check=True)

        with open(output_file_path, 'r') as f:
            bin_output = f.read()

        os.remove(output_file_path)

        result = self.read_ob_official_scan_result(bin_output)
        result = add_source_to_result(result, "ob")
        result = add_path_to_result(result, ip)
        return result


    def read_ob_official_scan_result(self,output):
        result=[]
        # 解析 JSON 数据
        try:
            data_list = json.loads(output)

            # 构造结果列表
            result = []
            for item in data_list:
                app_names = item.get("name", [])
                title = item.get("title", "")
                is_web = item.get("is_web", False)

                if len(app_names)<1 and is_web==True:
                    app_names=["http_server"]

                for app_name in app_names:
                    if len(app_name)>1:
                        result.append({"app_name": app_name, "match_string": title})
        except:
            pass

        return result

    def start(self,ip,port):
        result=[]
        url_list=["http://"+ip+":"+port,"https://"+ip+":"+port]
        for url in url_list:
            result.extend(self.webanalyze_scan(url))

        for url in url_list:
            result.extend(self.dismap_scan(url,None))

        result.extend(self.dismap_scan(ip, port))

        for url in url_list:
            result.extend(self.ob_official_scan(url,None))

        fingerprint_custom=Fingerprint_custom(is_test=IS_TEST)
        result.extend(fingerprint_custom.start(ip,port))

        return result


if __name__ == '__main__':
    finger_print = FingerPrint()

    ip = "1.1.1.148"
    port = 8889
    port=str(port)

    result=finger_print.start(ip,port)
    for item in result:
        print(item)

