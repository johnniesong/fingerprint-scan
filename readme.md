# 简介
资产服务及指纹扫描  
没有重复造轮子,整合优选后的开源项目实现.  
原本扫描完会入库,为了简化,当前改为直接print到控制台,可以自行diy

# 安装
需要安装三方软件,安装后的可执行文件路径填在config中
1. masscan
2. nmap
3. WEBANALYZE
4. DISMAP
5. DALFOX
6. OBSERVER
7. zenika/alpine-chrome(需docker安装)

# 运行
修改config\在asset_scan_main.py中修改扫描目标,python3 asset_scan_main.py执行

# 程序流程
1. 确定扫描目标,如ip,域名
2. 调用masscan确定开放端口
3. 调用nmap确定开放的服务指纹,如http
4. 调用开源指纹识别库进行指纹识别,当前选用WEBANALYZE,DISMAP,DALFOX,OBSERVER这四款
5. 调用自定义指纹识别
6. 输出结果

# 自定义指纹识别
逻辑在fingerprint_custom.py中,自定义指纹在data/fingerprint_data.json中,可以仿照填写,会调用zenika/alpine-chrome无头浏览器获取动态渲染后的结果,对于写指纹来说更加友好

# 文件说明
asset_scan_main.py 主程序
fingerprint_custom.py 自定义指纹识别
fingerprint_update.py 更新指纹,建议定期执行

# 引用的几个三方软件
1. https://github.com/0x727/ObserverWard   作为主力,对指纹编辑更加友好,指纹有更新源
2. https://github.com/rverton/webanalyze 
3. https://github.com/zhzyker/dismap 已不更新