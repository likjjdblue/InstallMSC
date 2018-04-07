#!/usr/bin/env python
#-*- coding: utf-8 -*-

import subprocess
import socket
from socket import inet_aton
from os import geteuid,path,makedirs,rename,environ,rename
import re
from re import match
from time import sleep
import json
import httplib
import sys
from resource import setrlimit,getrlimit,RLIMIT_NOFILE
from JSONScript import JSONScript


'''该脚本按照《微服务平台单节点搭建》中的步骤对服务器
进行配置，并安装相关的介质
'''

TextColorRed='\x1b[31m'
TextColorGreen='\x1b[32m'
TextColorWhite='\x1b[0m'

EnableLocalYum=False

validAppNameList=['java','kong','cassandra',
                 'elasticsearch','logstash'
                 ,'mariadb']

AppInstalledState={}

WikiURL='http://t.cn/REQVj8w'         #### WIKI 部署文档短地址   ##

def checkRootPrivilege():
###  检查脚本的当前运行用户是否是 ROOT ###
  RootUID=subprocess.Popen(['id','-u','root'],stdout=subprocess.PIPE).communicate()[0]
  RootUID=RootUID.strip()
  CurrentUID=geteuid()
  return str(RootUID)==str(CurrentUID)

def extractLocalIP():
    return subprocess.Popen("ip addr|grep 'state UP' -A2|tail -n1|awk '{print $2}'|cut -f 1 -d '/'",
                            shell=True,stdout=subprocess.PIPE).communicate()[0].strip()

def checkPortState(host='127.0.0.1',port=9200):
### 检查对应服务器上面的port 是否处于TCP监听状态 ##

    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(1)
    try:
       s.connect((host,port))
       return {'RetCode':0,
               'Result':TextColorGreen+str(host)+':'+str(port)+'处于监听状态'+TextColorWhite}
    except:
       return {'RetCode':1,
               'Result':TextColorRed+'无法访问'+str(host)+':'+str(port)+TextColorWhite}

def __checkOSVersion():
    #### 检查操作系统的版本，确保是Centos 7 的版本 ###
    OSInfoFileList=['/etc/centos-release']
    for filepath in OSInfoFileList:
      if path.isfile(filepath):
         TmpFileObj=open(filepath,mode='r')
         FileContent=TmpFileObj.read()
         FileContent=FileContent.strip()
         TmpFileObj.close()
         ReObj=re.search(r'\s+([\d\.]+)\s+',FileContent)
         if ReObj and ('CentOS' in FileContent):
            OSVersion=ReObj.group(1)
            if re.search(r'^7.*',OSVersion):
               print (TextColorGreen+'操作系统满足要求!'+TextColorWhite)
               return 0
            else:
               print (TextColorRed+'操作系统不满足要求(需要CentOS7)，当前系统:'+str(FileContent)+'\n程序退出!'+TextColorWhite)
               exit(1)
    print (TextColorRed+'无法获取操作系统版本信息，或者版本不符合要求(需要CentOS7)'+'\n程序退出!'+TextColorWhite)
    exit(1)

def isIPValid(ip):
    if not isinstance(ip,str) and not isinstance(ip,unicode):
        return False
    ## 检查IP 地址是否有效###
    ip=ip.strip()
    if len(ip.split('.'))==4:
        try:
            inet_aton(ip)
            tmpList=filter(lambda x:match(r'^[^0]+',x) or match(r'^0$',x),ip.split('.'))
            if len(tmpList)!=4:
                return False
            return True
        except:
            return False
    return False



def checkInternetConnection():
    global EnableLocalYum
    if EnableLocalYum:
        print ('当前开启了本地YUM源，跳过对互联网的检测.')
        return {'RetCode':0,
                'Description':'当前开启了本地YUM源，跳过对Internet的检测'}
    pingResult,pingError=subprocess.Popen(['ping','61.139.2.69','-c 2','-W 1'],stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()
    ReObj=re.search(r'(\d+)\s+received',pingResult)
    PacketRecived=int(ReObj.group(1))

    DNSResult,DNSError=subprocess.Popen(['ping','www.baidu.com','-c 1','-W 1'],stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()

    if PacketRecived>0 and DNSResult:
        return {'RetCode':0,
                 'Description':'网络畅通，DNS解析正常'}
    elif PacketRecived>0 and DNSError:
        return {'RetCode':1,
                 'Description':'网络畅通，DNS解析异常，请检查DNS服务器设置'}
    else:
        return {'RetCode':2,
                'Description':'无法连接互联网'}



def sendHttpRequest(host='127.0.0.1',port=9200,url='/',method='GET',body={},header={}):
#### 调用特定的 web API,并获取结果 ###
### 函数返回Dict 类型，其中'RetCode'，标识是否异常 0:正常，非0：异常
### 'Result'是具体结果

     try:
        if (not isinstance(body,dict)) or (not isinstance(header,dict)):
            raise Exception(TextColorRed+"需要传入Dict类型，参数调用异常！"+TextColorWhite)

        tmpBody=json.dumps(body)
        HttpObj=httplib.HTTPConnection(host,port)
        HttpObj.request(url=url,method=method,body=tmpBody,headers=header)
        response=json.loads(HttpObj.getresponse().read())
        return {'RetCode':0,
                 'Result':response}
     except Exception as e:
       return {'RetCode':1,
               'Result':TextColorRed+str(e)+TextColorWhite}


def configureServerArgument():
#### 修改/etc/security/limits.conf 将max open-file-descriptors 修改成65535
#### 由于不确定业务账号与平台的关联性，因此可能存在部分账号nofile 参数值
#### 被调大的可能性。

    if not  checkRootPrivilege():
       print (TextColorRed+"安装失败：安装过程需要使用root账号，请切换至root账号，然后重试!"+TextColorWhite)
       exit(1)

    #### 修改前先备份原始文件 ####
    if not path.isfile(r'/etc/security/limits.conf.backup'):
        subprocess.call(['cp','/etc/security/limits.conf','/etc/security/limits.conf.backup'])

    ReObj=re.compile(r'^\s*[^#]*nofile\s*(?P<value>\d*)\s*$')
    InputFile=open(r'/etc/security/limits.conf',mode='r')

    FileContent=''
    for line in InputFile:       ###逐行读取limits.conf，如果当前行配置了nofile且值低于65535,那么值将被修改成65535
       RetObj=ReObj.search(line)
       if RetObj and int(RetObj.group('value'))<65535:
           line=re.sub(r'(^\s*[^#]*nofile\s*)(?P<value>\d*)\s*$',r'\1 65535',line)
           FileContent+=line+'\n'
           continue
       FileContent+=line
    InputFile.close()

    Matched=re.search(r'#+.*?Codes below.*?#+',FileContent)
    if not Matched:
       FileContent+='#### Codes below are manually added #####\n'
       FileContent+='*     -    nofile    65535\n'

    OutputFile=open(r'/etc/security/limits.conf',mode='w')
    OutputFile.write(FileContent)
    OutputFile.close()

    ### 在当前脚本环境中将nofile设置成65535 ###
    setrlimit(RLIMIT_NOFILE,(65535,65535))



def installJava():
    try:
       JavaVersionString=subprocess.Popen(['/TRS/APP/jdk1.8/bin/java','-version'],stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()[1]
    except Exception as e:
       JavaVersionString=str(e)
    ReObj=re.search(r'java version\s+(.*?)\n',JavaVersionString)

    if ReObj and ReObj.group(1).strip('"').startswith('1.8'):
       print (TextColorGreen+'JAVA 版本满足要求(需要JAVA版本8):'+str(ReObj.group(1).strip('"'))+TextColorWhite)
       AppInstalledState['java']='ok'
    else:
       print (TextColorRed+'JAVA版本不满足要求（需要JAVA版本8)！'+TextColorWhite)
       print ('即将安装JAVA 8,请耐心等待........')

       try:
          makedirs('/TRS/APP')
          print (TextColorGreen+'/TRS/APP/目录创建成功!'+TextColorWhite)
       except:
          if not path.isdir('/TRS/APP'):
             print (TextColorRed+'无法创建/TRS/APP/目录，程序退出!'+TextColorWhite)
             AppInstalledState['java']='not ok'
             exit(1)

          print (TextColorGreen+'/TRS/APP目录已经存在，无需新建!'+TextColorWhite)
       finally:
          pass

       result,error=subprocess.Popen(['tar','-C','/TRS/APP/','-xvzf','install_package/jdk-8u111-linux-x64.tar.gz'],\
                                   stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()


       if len(error)>0:
          print (TextColorRed+error+TextColorWhite)
          print (TextColorRed+'错误：无法解压JAVA安装包,程序退出!'+TextColorWhite)
          AppInstalledState['java']='not ok'
          exit(1)
       print (TextColorGreen+'JAVA8压缩包解压完成!'+TextColorWhite)
       try:
          rename(r'/TRS/APP/jdk1.8.0_111','/TRS/APP/jdk1.8')
          print (TextColorGreen+'文件夹已经重命名为jdk1.8'+TextColorWhite)
       except:
          print (TextColorRed+'/TRS/APP目录下包含有一个名为jdk1.8 的文件或目录，重命名操作失败。')
          print(TextColorRed+'请删除或备份该目录（文件夹），并重新运行该脚本!\n'+'安装失败，程序退出!'+TextColorWhite)
          AppInstalledState['java']='not ok'
          exit(1)


    #### 配置JAVA 环境变量####
    print ('正在配置JAVA 环境变量，请稍等..........')
    JavaEnvironDict={'JAVA_HOME':'/TRS/APP/jdk1.8',\
            'PATH':'$JAVA_HOME/bin:$PATH',\
            'CLASSPATH':'.:$JAVA_HOME/lib/dt.jar:$JAVA_HOME/lib/tools.jar',
            'JRE_HOME':'/TRS/APP/jdk1.8/jre',
            }
    tmpDict={'JAVA_HOME':environ.get('JAVA_HOME'),\
             'PATH':environ.get('PATH'),
             'CLASSPATH':environ.get('CLASSPATH'),
             'JRE_HOME':environ.get('JRE_HOME')
            }

    if tmpDict['JAVA_HOME']!=JavaEnvironDict['JAVA_HOME'] or tmpDict['CLASSPATH']!=JavaEnvironDict['CLASSPATH']:
       environ['JAVA_HOME']=JavaEnvironDict['JAVA_HOME']
       environ['CLASSPATH']=JavaEnvironDict['CLASSPATH']
       environ['PATH']=JavaEnvironDict['JAVA_HOME']+'/bin:'+tmpDict['PATH']
       environ['JRE_HOME']=JavaEnvironDict['JAVA_HOME']+'/jre'

### 检查/etc/profile中是否永久配置了JAVA 环境变量###
    InputFile=open(r'/etc/profile','r')
    FileContent=InputFile.read()
    InputFile.close()

    ReObjA=re.search(r'^\s*export\s*JAVA_HOME=/TRS/APP/jdk1\.8\n',FileContent,flags=re.MULTILINE) ## 检查JAVA_HOME ###
    ReObjB=re.search(r'^\s*export\s*CLASSPATH=\.:\$JAVA_HOME/lib/dt\.jar:\$JAVA_HOME/lib/tools\.jar\s*\n',FileContent,flags=re.MULTILINE) ## 检查CLASSPATH ##
    ReObjC=re.search(r'^\s*export\s*JRE_HOME=/TRS/APP/jdk1\.8/jre/?\n',FileContent,flags=re.MULTILINE) ###检查JRE_HOME ###

    if (not ReObjA) or (not ReObjB) or (not ReObjC):
       if not path.isfile(r'/etc/profile.backup'):   ###修改前备份/etc/profile ###
          subprocess.call(['cp','/etc/profile','/etc/profile.backup'])

       OutputFile=open(r'/etc/profile',mode='a')
       OutputFile.write('\n')
       OutputFile.write('export  JAVA_HOME='+JavaEnvironDict['JAVA_HOME']+'\n')
       OutputFile.write('export  PATH='+JavaEnvironDict['PATH']+'\n')
       OutputFile.write('export  CLASSPATH='+JavaEnvironDict['CLASSPATH']+'\n')
       OutputFile.write('export  JRE_HOME='+JavaEnvironDict['JRE_HOME']+'\n')
       OutputFile.close()
    AppInstalledState['java']='ok'
    print (TextColorGreen+'JAVA 环境变量配置完毕!'+TextColorWhite)



def installCassandra():
    ### 对cassandra 进行解压，并添加cassandra系统账号####
    if path.isfile(r'/TRS/APP/cassandra/bin/cassandra'):
        print (TextColorGreen+'/TRS/APP目录下已经存在Cassendra安装目录，无需重复安装'+TextColorWhite)
        return 0
    print ('即将安装Cassandra请稍后.....')
    if subprocess.call('id -u cassandra',shell=True):
       print ('cassandra 账号不存在，需新建')
       subprocess.call('useradd cassandra',shell=True)
    print (TextColorGreen+'新建cassandra 账号完毕'+TextColorWhite)

    if path.exists(r'/TRS/APP/cassandra'):
        print (TextColorRed+'/TRS/APP目录下已经存在名为cassandra的文件或目录，Cassandra安装失败，程序退出!'+TextColorWhite)
        exit(1)
    subprocess.call('mkdir -p /TRS/APP',shell=True)
    subprocess.call(r'tar -C /TRS/APP -xvzf install_package/apache-cassandra-3.11.2-bin.tar.gz',shell=True)
    rename(r'/TRS/APP/apache-cassandra-3.11.2',r'/TRS/APP/cassandra')
    print (TextColorGreen+'Cassandra压缩包解压完毕.'+TextColorWhite)

    subprocess.call('chown -R cassandra:cassandra /TRS/APP/cassandra',shell=True)

    ####添加path 环境变量,开放防火墙   ###
    with open(r'/etc/profile',mode='r') as f:
        TmpFileContent=f.read()
    Matched=re.search(r'^\s*export\s+PATH=$\{PATH\}:/TRS/APP/cassandra/bin\n',TmpFileContent,
                      flags=re.MULTILINE)
    if not Matched:
        ##修改前先备份  ##
        with open(r'/etc/profile.backup',mode='w') as f:
            f.write(TmpFileContent)

        TmpFileContent=TmpFileContent+'\n'+'export PATH=${PATH}:/TRS/APP/cassandra/bin'+'\n'
        with open(r'/etc/profile',mode='w') as f:
            f.write(TmpFileContent)
        subprocess.call('source /etc/profile',shell=True)
    subprocess.call('firewall-cmd --zone=public --add-port=7000/tcp --permanent',shell=True)
    subprocess.call('firewall-cmd --zone=public --add-port=9042/tcp --permanent',shell=True)
    subprocess.call('firewall-cmd --reload',shell=True)
    print (TextColorGreen+'PATH 环境变量设置完毕'+TextColorWhite)

    ### 设置启动脚本  ##
    with open(r'install_package/cassandra',mode='r') as f:
        TmpFileContent=f.read()
    with open(r'/etc/init.d/cassandra',mode='w') as f:
        f.write(TmpFileContent)
    subprocess.call('chmod 777 /etc/init.d/cassandra',shell=True)
    subprocess.call('systemctl daemon-reload',shell=True)

    print ('正在启动Cassendra，请稍候....')
    if subprocess.call('systemctl start cassandra',shell=True):
        print (TextColorRed+'无法启动Cassandra，程序退出'+TextColorWhite)
        exit(1)

    sleep(10)
    print (TextColorGreen+'Cassandra启动成功.'+TextColorWhite)
    AppInstalledState['cassandra']='ok'


def installKong():
    if not subprocess.call('which kong',shell=True):
        print (TextColorGreen+'Kong 已经安装，无需重复安装'+TextColorWhite)
        return 0

    InternetState=checkInternetConnection()
    if InternetState['RetCode']!=0:
        print (TextColorRed+InternetState['Description']+'程序退出!'+TextColorWhite)
        exit(1)
    subprocess.call('yum install perl -y ',shell=True)

    print ('即将安装Lua ,请稍候....')
    if subprocess.call('rpm -Uvh --force install_package/lua_packages/*.rpm',shell=True):
        print (TextColorRed+'安装Lua失败，程序退出'+TextColorWhite)
        exit(1)
    print (TextColorGreen+'Lua安装完毕.'+TextColorWhite)

    if subprocess.call('rpm -Uvh --force install_package/kong_packages/kong-community-edition-0.11.2.el7.noarch.rpm',
                       shell=True):
        print (TextColorRed+'Kong安装失败，程序退出.'+TextColorWhite)
        exit(1)
    with open(r'install_package/kong_packages/kong.conf',mode='r') as f:
        TmpFileContent=f.read()
    with open(r'/etc/kong/kong.conf',mode='w') as f:
        f.write(TmpFileContent)

    if subprocess.call('luarocks install install_package/kong_packages/kong-plugin-non-restful-request-filter-0.1.0-1.all.rock',shell=True):
        print (TextColorRed+'Kong插件安装失败，程序退出'+TextColorWhite)
        exit(1)
    if subprocess.call('luarocks install install_package/kong_packages/kong-plugin-msc-http-log-0.1.0-1.all.rock',shell=True):
        print (TextColorRed+'Kong插件安装失败，程序退出'+TextColorWhite)
        exit(1)

    if subprocess.call('kong migrations up',shell=True):
        print (TextColorRed+'Kong迁移操作失败，程序退出'+TextColorWhite)
        exit(1)

    if subprocess.call('kong start',shell=True):
        print (TextColorRed+'Kong 启动失败，程序退出.'+TextColorWhite)
        exit(1)

    subprocess.call('firewall-cmd --zone=public --add-port=8001/tcp --permanent',shell=True)
    subprocess.call('firewall-cmd --zone=public --add-port=9001/tcp --permanent',shell=True)
    subprocess.call('firewall-cmd --zone=public --add-port=8000/tcp --permanent',shell=True)
    subprocess.call('firewall-cmd --zone=public --add-port=8443/tcp --permanent',shell=True)
    subprocess.call('firewall-cmd --zone=public --add-port=8444/tcp --permanent',shell=True)
    subprocess.call('firewall-cmd --reload',shell=True)

    isKongUP=False
    for itime in range(7):
        PortState=checkPortState('127.0.0.1',8001)
        if PortState['RetCode']==0:
            print (TextColorGreen+'Kong 8001 端口处于监听状态'+TextColorWhite)
            isKongUP=True
            break
        print (TextColorRed+'Kong 8001端口未开放，尝试等待次数：'+str(itime+1)+TextColorWhite)

    if not isKongUP:
        print (TextColorRed+'Kong 8001端口未开放，,Kong安装失败,程序退出。'+TextColorWhite)
        exit(1)

    TmpResult=sendHttpRequest(host='127.0.0.1',port=8001,url='/plugins',method='POST',
                    body=JSONScript.MscHttpLog,header={'Content-Type':'application/json'})
    print (TmpResult)
    TmpResult=sendHttpRequest(host='127.0.0.1',port=8001,url='/plugins',method='POST',
                    body=JSONScript.Cors,header={'Content-Type':'application/json'})
    print (TmpResult)
    TmpResult=sendHttpRequest(host='127.0.0.1',port=8001,url='/plugins',method='POST',
                    body=JSONScript.keyAuth,header={'Content-Type':'application/json'})
    print (TmpResult)
    TmpResult=sendHttpRequest(host='127.0.0.1',port=8001,url='/plugins',method='POST',
                    body=JSONScript.RequestTransformer,header={'Content-Type':'application/json'})
    print (TmpResult)

    ### 设置custom_plugins  directive   ####
    with open(r'/etc/kong/kong.conf',mode='r') as f:
        TmpFileContent=f.read()

    TmpFileContent=TmpFileContent+'\n'+'### Codes below are manually added ####\n'
    TmpFileContent=TmpFileContent+'custom_plugins = '+'msc-http-log'+'\n'
    with open(r'/etc/kong/kong.conf',mode='w') as f:
        f.write(TmpFileContent)

    print (TextColorGreen+'Kong 安装完毕'+TextColorWhite)
    AppInstalledState['kong']='ok'


def installElasticsearch():
    LocalIPAddr=extractLocalIP()
    if subprocess.call('id -u es',shell=True):  ###首先检查es 账号是否存在###
       print ('ES 账户不存在，需新建。')
       subprocess.call('useradd es',shell=True)
       print (TextColorGreen+'新建ES 账号完成'+TextColorWhite)
       subprocess.call('passwd -l es',shell=True) ####对于通过脚本新建的 es 账号，默认是锁定的(避免弱口令)；其他方式的不受影响###
    else:
       print (TextColorGreen+"ES 账号已经存在。"+TextColorWhite)

    if not path.isdir(r'/TRS/APP'):
       subprocess.call('mkdir -p /TRS/APP/',shell=True)

    if path.exists(r'/TRS/APP/elasticsearch'):
       print (TextColorRed+'检测到/TRS/APP 目录下已经存在一个名为"elasticsearch"的文件或目录，')
       print (TextColorRed+'请删除或对其进行重命名，并重新运行该工具。')
       print (TextColorRed+'Elasticsearch 安装失败，程序退出!'+TextColorWhite)
       AppInstalledState['elasticsearch']='not ok'
       exit(1)

    subprocess.call('tar -C /TRS/APP -xvzf install_package/elasticsearch-5.5.0.tar.gz',shell=True)
    rename(r'/TRS/APP/elasticsearch-5.5.0',r'/TRS/APP/elasticsearch')
    print (TextColorGreen+'Elasticsearch压缩包解压完毕。')

    subprocess.call("sed -i 's/#network\.host: 192\.168\.0\.1/network\.host: 0\.0\.0\.0/g' /TRS/APP/elasticsearch/config/elasticsearch.yml",
                    shell=True)

    print (TextColorGreen+'Elasticsearch解压完毕。'+TextColorWhite)

#### 修改操作系统参数 ###

    FileObj=open(r'/etc/security/limits.conf',mode='rb')  ####永久修改 nofile  ###
    FileContent=FileObj.read()
    FileObj.close()

    ReObjA=re.search(r'^\s*es\s+hard\s+nofile\s+(\d+)\s*$',FileContent,flags=re.MULTILINE)
    ReObjB=re.search(r'^\s*es\s+soft\s+nofile\s+(\d+)\s*$',FileContent,flags=re.MULTILINE)
    ReObjC=re.search(r'^\s*es\s+-\s+nofile\s+(\d+)\s*$',FileContent,flags=re.MULTILINE)

    if ((not ReObjA) or (not ReObjB)) and (not ReObjC):
       if not path.isfile(r'/etc/security/limits.conf.backup'):  ### 修改前先备份  ##
          subprocess.call('cp /etc/security/limits.conf /etc/security/limits.conf.backup',shell=True)
       subprocess.call("echo 'es - nofile 65536' >>/etc/security/limits.conf",shell=True)


####   检查 /etc/sysctl.conf 中vm.max_map_count  的配置情况 ###
    if not path.isfile(r'/etc/sysctl.conf.backup'):
       subprocess.call('cp /etc/sysctl.conf /etc/sysctl.conf.backup',shell=True)

    FileObj=open(r'/etc/sysctl.conf',mode='rb')
    FileContent=FileObj.read()
    FileObj.close()

    tmpList=list(int(x) for x in re.findall(r'^\s*vm.max_map_count\s*=\s*(\d*)\s*$',FileContent,flags=re.MULTILINE))

    if len(tmpList)==0:   ###没有在 /etc/sysctl.conf  中配置vm.max_map_count ###
       subprocess.call("echo 'vm.max_map_count = 655360' >>/etc/sysctl.conf",shell=True)
    elif (len(tmpList)>=1 and max(tmpList)<655360) or (tmpList[-1]<655360):   #### 修正/etc/sysctl.conf 中不不符合要求的vm.max_map_count 参数
       ###首先，删除垃圾数据;然后重新写入###
       FileContent=re.sub(r'^\s*vm.max_map_count\s*=\s*(\d*)\s*$',r'',FileContent,flags=re.MULTILINE)
       FileObj=open(r'/etc/sysctl.conf',mode='wb')
       FileObj.write(FileContent)
       FileObj.write('vm.max_map_count = 655360'+'\n')
       FileObj.close()


    subprocess.call("chown -R es:es /TRS/APP/elasticsearch",shell=True)

    print (TextColorGreen+'Elasticsearch 系统参数配置完毕.'+TextColorWhite)

    ####   添加分词器插件  ####
    subprocess.call('mkdir -p /TRS/APP/elasticsearch/plugins/ik',shell=True)
    subprocess.call('tar -C /TRS/APP/elasticsearch/plugins  -xvzf install_package/ik-ly.5.5.0.tar.gz',shell=True)
    subprocess.call("chown -R es:es /TRS/APP/elasticsearch",shell=True)
    print (TextColorGreen+'elasticsearch分词器安装完毕!'+TextColorWhite)


    isElasticRunning=False
    subprocess.call('sysctl vm.max_map_count=655360;su - es -c /TRS/APP/elasticsearch/bin/elasticsearch &',
                    shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    print ('正在尝试启动elasticsearch，请稍候......')
    for icount in range(7):
         print ('尝试次数:'+str(icount+1))
         sleep(7)
         is9200Listening=checkPortState('127.0.0.1',9200)['RetCode']
         if is9200Listening==0:
            print (TextColorGreen+'Elasticsearch 正在监听9200端口。'+TextColorWhite)
            isElasticRunning=True
            break
         else:
             sleep(5)

    if not isElasticRunning:
         print (TextColorRed+'无法启动Elasticsearch'+TextColorWhite)
         AppInstalledState['elasticsearch']='not ok'
         exit(1)

    ### 创建 index ####
    tmpresult=sendHttpRequest(host='127.0.0.1',port=9200,url='/msc_log',method='PUT',header={'Content-Type':'application/json'})
    print (tmpresult)
    tmpresult=sendHttpRequest(host='127.0.0.1',port=9200,url='/msc_log/logs/_mapping',method='POST',
                              header={'Content-Type':'application/json'},body=JSONScript.MscLog)
    print (tmpresult)


    print (TextColorGreen+'Elasticsearch  已经成功安装并配置。'+TextColorWhite)
    AppInstalledState['elasticsearch']='ok'

def configElasticsearch():
    ### 复用其他产品的Elasticsearch ,进行简单的配置####
    TmpIP=raw_input('输入需要配置的Elasticsearch IP地址：')
    TmpIP=TmpIP.strip()

    if not isIPValid(TmpIP):
        print (TextColorRed+'输入的IP地址无效： '+str(TmpIP)+TextColorWhite)
        return 1

    is9200Listening=checkPortState(TmpIP,9200)['RetCode']
    if is9200Listening!=0:
        print (TextColorRed+str(TmpIP)+' :9200 未处于监听状态，无法进行配置'+TextColorWhite)
        return 1
    print (TextColorGreen+str(TmpIP)+':9200 监听正常'+TextColorWhite)

    tmpresult=sendHttpRequest(host=TmpIP,port=9200,url='/msc_log',method='PUT',header={'Content-Type':'application/json'})
    print (tmpresult)
    tmpresult=sendHttpRequest(host=TmpIP,port=9200,url='/msc_log/logs/_mapping',method='POST',
                              header={'Content-Type':'application/json'},body=JSONScript.MscLog)
    print (tmpresult)

    print (TextColorGreen+'成功配置Elasticsearch@'+TmpIP+':9200'+TextColorWhite)


def installLogstash():
   if path.exists(r'/TRS/APP/logstash'):
      print (TextColorRed+'/TRS/APP 目录下已经存在一个名为logstash的文件或目录，请对其删除或重命名备份，'+TextColorWhite)
      print (TextColorRed+'然后重新运行本工具。'+TextColorWhite)
      print (TextColorRed+'logstash安装失败！\ 程序退出。'+TextColorWhite)
      AppInstalledState['logstash']='not ok'
      exit(1)

   if not path.isdir(r'/TRS/APP'):
     subprocess.call('mkdir -p /TRS/APP',shell=True)

   print ('即将解压Logstash,请稍候......')
   subprocess.call('tar -C /TRS/APP -xvzf install_package/logstash-5.5.0.tar.gz',shell=True)
   rename(r'/TRS/APP/logstash-5.5.0',r'/TRS/APP/logstash')
   print (TextColorGreen+'Logstash解压完毕。'+TextColorWhite)
   AppInstalledState['logstash']='ok'
   print (TextColorGreen+'请访问如下地址，完成后续的logstash 配置操作！\n'+WikiURL+TextColorWhite)


def installMariadb():
    ### 通过YUM 方式安装 mariadb ###
    global EnableLocalYum
    print ('安装说明：')
    print ('1、安装过程将通过YUM 方式从官方仓库进行安装，如果不希望采用该方式请终止本程序；')
    print ('2、本程序只进行基本安装，请按照WIKI要求及实际需求自行对mariadb进行必要的配置；')
    print ('    配置项包括但不仅限于字符集，最大连接数，大小写敏感，以及必要的安全配置，数据存放路径。')
    print ('3、安装完毕后将使用/etc/my.cnf 配置文件；')

    while True:
        isContinue=raw_input("是否继续(Yes/No):")
        isContinue=isContinue.strip().lower()

        if isContinue=='yes' or isContinue=='y':
            break
        elif isContinue=='no' or isContinue=='n':
            return 1
    print ('即将安装Mariadb,请稍候......')

    if EnableLocalYum==True:
        print (TextColorRed+'检测到当前开启了本地YUM 开关，当前不支持本地安装方式，无法继续.'+TextColorWhite)
        return 1

    InternetState=checkInternetConnection()
    if InternetState['RetCode']!=0:
        print (TextColorRed+InternetState['Description']+' 安装Mariadb 失败，程序退出.'+TextColorWhite)
        exit(1)
    with open(r'install_package/mariadb_conf/MariaDB.repo',mode='r') as f:
        TmpFileContent=f.read()
    with open(r'/etc/yum.repos.d/MariaDB.repo',mode='w') as f:
        f.write(TmpFileContent)

    if subprocess.call('yum install MariaDB-server MariaDB-client -y',shell=True):
        print (TextColorRed+'安装Mariadb失败，程序退出.'+TextColorGreen)
        exit(1)
    print ('安装完毕，进行初始化....')

    try:
        if not path.isfile(r'/etc/my.cnf.backup'):
            subprocess.call('cp /etc/my.cnf /etc/my.cnf.backup',shell=True)
    except:
        pass

    with open(r'install_package/mariadb_conf/my.cnf',mode='r') as f:
        TmpFileContent=f.read()
    with open(r'/etc/my.cnf',mode='w') as f:
        f.write(TmpFileContent)

    print (TextColorGreen+'已经成功安装Mariadb'+TextColorWhite)
    print ('请手动对mariadb进行必要的配置，配置内容包括：为root账号设置密码、指定数据的存放目录等.')
    AppInstalledState['mariadb']='ok'


def __preInstall():
   __checkOSVersion()

   global EnableLocalYum

   for index in range(len(sys.argv)):
       if sys.argv[index]=='-localyum':
          EnableLocalYum=True
          print (TextColorGreen+'当前开启了本地YUM 开关'+TextColorWhite)
          break


   try:
      LocalIP=extractLocalIP()
      ### 读取之前已经安装的介质信息，避免重复安装  ###
      if path.isfile(str(LocalIP)+'.log'):
         InputFile=open(LocalIP+'.log',mode='r')
         for line in InputFile:
             TmpList=line.strip().split(':')
             if len(TmpList)>=2:
                name,value=str(TmpList[0]).strip().lower(),str(TmpList[1]).strip().lower()
                if (name in validAppNameList) and (value=='ok'):
                   AppInstalledState[name]=value
                else:
                   print (TextColorRed+'无效的内容'+line+TextColorWhite)
             else:
                 print (TextColorRed+'无效的内容'+line+TextColorWhite)
         InputFile.close()

      checkRootPrivilege()
      configureServerArgument()
   except Exception as e:
      print (TextColorRed+'预安装过程出错：'+str(e)+TextColorWhite)
   finally:
      pass

def __postInstall():
    try:
     	LocalIP=extractLocalIP()
    	FileObj=open(str(LocalIP)+'.log',mode='w')
    	for appname in AppInstalledState:
            if AppInstalledState[appname]=='ok':
               FileObj.write(appname+': '+'ok'+'\n')
               continue
            else:
               pass
        FileObj.close()
    except Exception as e:
          print (str(e))
          FileObj.close()
    finally:
          print(TextColorGreen+'介质的安装日志结果保存在当前目录下的:'+str(LocalIP)+'.log'+'文件当中!'+TextColorWhite)


def RunMenu():
    try:
       while True:
          print (TextColorGreen+'#########  欢迎使用“微服务平台”，本工具将帮助你完成基础介质的安装。  ######')
          print ('           1、安装 JAVA;')
          print ('           2、安装 Cassandra;')
          print ('           3、安装 Kong;')
          print ('           4、安装 Elasticsearch;')
          print ('           5、配置已有 Elasticsearch("对环境中现有的ES 进行复用")')
          print ('           6、安装Logstash')
          print ('           7、安装MariaDB(YUM 方式安装)')
          print ('           0、退出安装;'+TextColorWhite)

          choice=raw_input('请输入数值序号:')
          choice=choice.strip()

          if choice=='1':
             if ('java' in AppInstalledState) and (AppInstalledState['java']=='ok'):
                 print (TextColorGreen+'JAVA 已经安装，无需重复安装'+TextColorWhite)
                 continue
             installJava()
          elif choice=='2':
             if ('cassandra' in AppInstalledState) and (AppInstalledState['cassandra']=='ok'):
                 print (TextColorGreen+'Cassandra 已经安装，无需重复安装'+TextColorWhite)
                 continue
             installCassandra()
          elif  choice=='3':
             if ('kong' in AppInstalledState) and (AppInstalledState['kong']=='ok'):
                print (TextColorGreen+'Kong 已经安装，无需重复安装'+TextColorWhite)
                continue
             installKong()
          elif  choice=='4':
             if ('elasticsearch'  in AppInstalledState) and (AppInstalledState['elasticsearch']=='ok'):
                print (TextColorGreen+' Elasticsearch 已经安装，无需重复安装'+TextColorWhite)
                continue
             installElasticsearch()
          elif  choice=='5':
             configElasticsearch()
          elif choice=='6':
             if ('logstash' in AppInstalledState) and (AppInstalledState['logstash']=='ok'):
                print (TextColorGreen+'Nginx 已经安装，无需重复安装'+TextColorWhite)
                continue
             installLogstash()
          elif choice=='7':
             if ('mariadb' in AppInstalledState) and (AppInstalledState['mariadb']=='ok'):
                print (TextColorGreen+'Mariadb 已经安装，无需重复安装'+TextColorWhite)
                continue
             installMariadb()
          elif  choice=='0':
             exit(0)
    except Exception as e:
          print (str(e))
    finally:
          __postInstall()


if __name__=='__main__':
  try:
    __preInstall()
    RunMenu()
  except Exception as e:
    print (TextColorRed+'Error:'+str(e)+TextColorWhite)
  finally:
    __postInstall()
