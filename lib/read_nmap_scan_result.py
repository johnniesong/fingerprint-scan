import xml.etree.ElementTree as ET

def read_nmap_scan_result(xml_data):
    # 解析XML数据
    root = ET.fromstring(xml_data)

    # 创建字典，用于存储解析结果
    results = {}

    # 遍历 <host> 标签，提取信息
    for host in root.findall('host'):
        # 获取 IP 地址
        ip_address = host.find("address").get("addr")

        # 初始化IP对应的端口信息列表
        results[ip_address] = []

        # 遍历 <port> 标签
        for port in host.find('ports').findall('port'):
            # 提取端口信息
            service_info=port.find('service')
            if service_info!=None:
                service_name=port.find('service').get('name')
            else:
                service_name=''

            port_info = {
                'port': port.get('portid'),
                'state': port.find('state').get('state'),
                'service': service_name
            }

            # 尝试获取版本信息，如果存在
            if service_info!=None:
                version = port.find('service').get('product')
                port_info['version'] = version if version else ''
            else:
                port_info['version'] = ''

            # 将端口信息添加到IP地址对应的列表中
            results[ip_address].append(port_info)

    # 打印结果
    print(results)
    return results


if __name__ == '__main__':
    xml_data = """"""
    read_nmap_scan_result(xml_data)