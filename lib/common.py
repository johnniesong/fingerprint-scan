import socket,ipaddress,re,hashlib,json,pickle
from concurrent.futures import ThreadPoolExecutor
from config import *

def save_obj_to_file(obj,filename):
    with open(filename+".pickle", 'wb') as f:  # open file with write-mode
        picklestring = pickle.dump(obj, f)  # serialize and save object

def load_obj_from_file(filename):
    with open(filename+".pickle", 'rb') as f:  # open file with
        pickleobj = pickle.load(f)  # unserialize and load object
    return pickleobj


def get_md5_hash(content):
    """ 计算字符串的MD5 """
    md5 = hashlib.md5()
    md5.update(content)
    return md5.hexdigest()

def replace_letters_numbers(s):
    """将字符串中的所有字母替换为 'a'，所有连续的数字替换为 '0'。"""
    # 替换所有字母为 'a'
    s = re.sub(r'[a-zA-Z]', 'a', s)
    # 替换所有连续的数字为单个 '0'
    s = re.sub(r'\d+', '0', s)
    return s


def generate_md5_hash(content):
    # 创建MD5对象
    md5 = hashlib.md5()
    # 对提供的内容进行编码，并更新MD5对象
    md5.update(content.encode('utf-8'))
    # 返回十六进制的摘要字符串
    return md5.hexdigest()


def add_source_to_result( result, source):
    for item in result:
        item.update({"source": source})
    return result


def add_path_to_result(result, path):
    for item in result:
        item.update({"path": path})
    return result

def is_ip_address(string):
    try:
        ipaddress.ip_address(string)
        return True
    except ValueError:
        return False


# 解析域名并返回结果
def resolve_hostname(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        return hostname, ip_address
    except socket.gaierror:
        return hostname, None


# 解析域名列表并打印所有结果
def resolve_hostnames(hostnames):
    # 使用with语句自动管理线程池资源
    result={}
    max_worker=20
    with ThreadPoolExecutor(max_workers=max_worker) as executor:
        # 通过map函数提交任务并获取结果
        results = executor.map(resolve_hostname, hostnames)

        # 输出结果
        for hostname, ip_address in results:
            if ip_address:
                #print(f"域名 {hostname} 对应的IP地址是 {ip_address}")
                result.update({hostname: ip_address})
            else:
                print(f"域名 {hostname} 解析失败。")
                result.update({hostname: ""})

    return result



if __name__ == '__main__':
    # 域名列表
    hostnames = ['www.a.cn', ]

    # 解析域名列表
    resolve_hostnames(hostnames)