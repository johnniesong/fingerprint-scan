import json,os
import subprocess

from config import *
from lib.common import add_path_to_result,add_source_to_result

class Fingerprint_custom:
    def __init__(self,is_test):
        if is_test:
            self.o_fingerprint = "/Users/thirdScan/web_fingerprint_v3.json_bak"
            self.y_fingerprint = "/Users/Documents/git2/asset_scan/data/y_fingerprint_data.json"
        else:
            self.o_fingerprint = "/root/.config/observer_ward/web_fingerprint_v3.json"
            self.y_fingerprint = os.path.join(os.path.dirname(os.path.abspath(__file__)))+"/../data/fingerprint_data.json"

    # 读取 JSON 文件并合并数据
    def read_and_merge_json_files(self, *filenames):
        merged_data = []
        for filename in filenames:
            with open(filename, 'r') as file:
                data = json.load(file)
                merged_data.extend(data)
        return merged_data

    # 执行 Docker 命令获取响应体
    def get_response_body(self, url):
        try:
            result = subprocess.check_output(
                ['docker', 'container', 'run', '--rm', 'zenika/alpine-chrome',
                 '--no-sandbox', '--dump-dom', url],
                stderr=subprocess.STDOUT)
            return result.decode('utf-8')
        except subprocess.CalledProcessError as e:
            print(f"Error fetching URL {url}: {e.output.decode('utf-8')}")
            return None

    # 检查关键字匹配
    def check_keyword_match(self, response_body, keywords):
        if len(keywords) == 0:
            return False
        response_body = response_body.lower()
        for keyword in keywords:
            sanitized_keyword = keyword.replace("<title>", "").replace("</title>", "").lower()
            if sanitized_keyword not in response_body:
                return False
        return True

    # 检查特定 name 是否存在于结果中
    def check_name_in_results(self, results, names):
        for result in results:
            if result['name'].lower() in names:
                return True
        return False

    def read_result(self,json_data):
        result = []
        try:
            data_dict = json_data
            for key in data_dict:
                for item in data_dict[key]:
                    # 检查 'name' 和 'keyword' 是否存在，以及'name' 是否有内容
                    if 'name' in item and 'keyword' in item and len(item['name']) > 1:
                        app_name = item['name']
                        match_string = item['keyword']  # 假设我们需要整个keyword列表作为match_string
                        path = item['path']  # 假设我们需要整个keyword列表作为match_string
                        result.append({"app_name": app_name, "match_string": match_string,"path":path})
        except:
            pass

        return result

    def start(self,ip, port):
        o_fingerprint = self.o_fingerprint
        y_fingerprint = self.y_fingerprint
        data = self.read_and_merge_json_files(o_fingerprint, y_fingerprint)
        base_path = '/'
        results = {f"{ip}:{port}": []}
        base_urls = [f"http://{ip}:{port}{base_path}", f"https://{ip}:{port}{base_path}"]

        # 检查基本路径的响应体
        matched = False
        for url in base_urls:
            response = self.get_response_body(url)
            if response:
                for entry in data:
                    if entry['path'] == base_path and self.check_keyword_match(response, entry['keyword']):
                        results[f"{ip}:{port}"].append({"keyword": entry['keyword'], "name": entry['name'],"path":url})
                        if entry['name'].lower() in ['idaas', 'buc']:
                            matched = True

        # 如果基本路径匹配 name 为 idaas 或 buc，遍历其他路径
        if matched:
            unique_paths = set(entry['path'] for entry in data if entry['path'] != base_path)
            for path in unique_paths:
                urls = [f"http://{ip}:{port}{path}", f"https://{ip}:{port}{path}"]
                for url in urls:
                    response = self.get_response_body(url)
                    if response:
                        for entry in data:
                            if entry['path'] == path and self.check_keyword_match(response, entry['keyword']):
                                results[f"{ip}:{port}"].append({"keyword": entry['keyword'], "name": entry['name'],"path":url})


        result=self.read_result(results)
        result=add_source_to_result(result,"ob")
        return result


# 运行脚本
if __name__ == "__main__":
    handler = Fingerprint_custom(is_test=IS_TEST)
    ip_address = "a.a.cn"
    port_number = "443"

    result=handler.start(ip_address, port_number)
    for item in result:
        print(item)