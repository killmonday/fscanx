## 内置指纹库语法

指纹库位于: https://github.com/chainreactors/templates/tree/master/fingers

https://github.com/chainreactors/fingers/tree/master/fingers 为其规则库的go语言实现.

指纹分为tcp指纹、http指纹

tcp指纹与http指纹为同一格式, 但通过不同的文件进行管理

### 完整的配置

配置文件: `v2/templates/http/*` 与 `v2/templates/tcpfingers.yaml`

一个完整的配置:

```yaml
- name: frame   # 指纹名字, 匹配到的时候输出的值
  default_port: # 指纹的默认端口, 加速匹配. tcp指纹如果匹配到第一个就会结束指纹匹配, http则会继续匹配, 所以默认端口对http没有特殊优化
    - '1111'
  protocol: http  # tcp/http, 默认为http
  rule:
   - version: v1.1.1 # 可不填, 默认为空, 表示无具体版本
     regexps: # 匹配的方式
        vuln: # 匹配到vuln的正则, 如果匹配到, 会输出framework为name的同时, 还会添加vuln为vuln的漏洞信息
          - version:(.*) # vuln只支持正则,  同时支持版本号匹配, 使用括号的正则分组. 只支持第一组
        regexp: # 匹配指纹正则
          - "finger.*test" 
       # 除了正则, 还支持其他类型的匹配, 包括以下方式
        header: # 仅http协议可用, 匹配header中包含的数据
          - string
        body: # 包含匹配, 非正则表达式
          - string
        md5: # 匹配body的md5hash
          - [md5]
        mmh3: # 匹配body的mmh3hash
          - [mmh3]
          
        # 只有上面规则中的至少一条命中才会执行version
        version: 
          - version:(.*)  # 某些情况下难以同时编写指纹的正则与关于版本的正则, 可以特地为version写一条正则

     favicon: # favicon的hash值, 仅http生效
        md5:
          - f7e3d97f404e71d302b3239eef48d5f2
        mmh3:
          - '516963061'
     level: 1      # 0代表不需要主动发包, 1代表需要额外主动发起请求. 如果当前level为0则不会发送数据, 但是依旧会进行被动的指纹匹配.
     send_data: "info\n" # 匹配指纹需要主动发送的数据
     vuln: frame_unauthorized # 如果regexps中的vuln命中, 则会输出漏洞名称. 某些漏洞也可以通过匹配关键字识别, 因此一些简单的poc使用指纹的方式实现, 复杂的poc请使用-e下的nuclei yaml配置

```

为了压缩体积, 没有特别指定的参数可以留空会使用默认值。

在两个配置文件中包含大量案例可供参考。

但实际上大部分字段都不需要配置, 仅作为特殊情况下的能力储备。

每个指纹都可以有多个rule, 每个rule中都有一个regexps, 每个regexps有多条不同种类的字符串/正则/hash

## 配置案例

### 最简使用

在大多数情况下只需要匹配body中的内容。一个指纹插件最简配置可以简化为如下所示:

```
- name: tomcat
  rule:
    - regexps:
        body:
          - Apache Tomcat
```

这里的body为简单的strings.Contains函数, 判断http的body中是否存在某个字符串。

gogo中所有的指纹匹配都会忽略大小写。

### 匹配版本号

而如果要提取版本号, 配置也不会复杂多少。

```
- name: tomcat
  rule:
    - regexps:
        regexp:
          - <h3>Apache Tomcat/(.*)</h3>
          - <title>Apache Tomcat/(.*)</title>
```

### 通过version字段映射版本号

但是有些情况下, 版本号前后并没有可以用来匹配的关键字. 可以采用version字段去指定版本号。

例如：

```
- name: tomcat
  rule:
    - version: v8
      regexps:
        body:
          - <h3>Apache Tomcat/8</h3>
```

这样一来只需要匹配到特定的body, 在结果中也会出现版本号。

`[+] https://1.1.1.1:443    tomcat:v8 [200] Apache Tomcat/8.5.56 `

### 通过version规则匹配版本号

而一些更为特殊的情况, 版本号与指纹不在同一处出现, 且版本号较多, 这样为一个指纹写十几条规则是很麻烦的事情, gogo也提供了便捷的方法.

看下面例子:

```
- name: tomcat
  rule:
    - regexps:
        regexp:
          - <h3>Apache Tomcat/8</h3>
       	version:
       	  - Tomcat/(.*)</h3>
```

可以通过regexps中的version规则去匹配精确的版本号。version正则将会在其他匹配生效后起作用, 如果其他规则命中了指纹且没发现版本号时, 就会使用version正则去提取。

这些提取版本号的方式可以按需使用, 大多数情况下前面两种即可解决99%的问题, 第三种以备不时之需。

### 主动指纹识别

假设情况再特殊一点, 例如, 需要通过主动发包命中某个路由, 且匹配到某些结果。一个很经典的例子就是nacos, 直接访问是像tomcat 404页面, 且header中无明显特征, 需要带上/nacos路径去访问才能获取对应的指纹。

看gogo中nacos指纹的配置

```
- name: nacos
  focus: true
  rule:
    - regexps:
        body:
          - console-ui/public/img/favicon.ico
      send_data: /nacos
```

其中, send_data为主动发包发送的URL, 在tcp指纹中则为socket发送的数据。

当`http://127.0.0.1/nacos`中存在`console-ui/public/img/favicon.ico`字符串, 则判断为命中指纹。

这个send_data可以在每个rule中配置一个, 假设某个框架不同版本需要主动发包的URL不同, 也可以通过一个插件解决。

这里还看到了focus字段, 这个字段是用来标记一些重点指纹, 默认添加了一下存在常见漏洞的指纹, 也可以根据自己的0day库自行配置。在输出时也会带有focus字样, 可以通过`--filter focus` 过滤出所有重要指纹。

### 漏洞信息匹配

而还有情况下, 某些漏洞或信息会直接的以被动的形式被发现, 不需要额外发包。所以还添加了一个漏洞指纹的功能。

例如gogo中真实配置的tomcat指纹为例：

```
- name: tomcat
  rule:
    - regexps:
        vuln:
          - Directory Listing For
        regexp:
          - <h3>Apache Tomcat/(.*)</h3>
          - <title>Apache Tomcat/(.*)</title>
        header:
          - Apache-Coyote
      favicon:
        md5:
          - 4644f2d45601037b8423d45e13194c93
      info: tomcat Directory traversal
      # vuln: this is vuln title
```

regexps中配置了vuln字段, 这个字典如果命中, 则同时给目标添加上vuln输出, 也就是使用gogo经常看到的输出的末尾会添加`[ info: tomcat Directory traversa]` 

这里也有两种选择info/vuln, info为信息泄露、vuln为漏洞。当填写的是vuln, 则输出会改成`[ high: tomcat Directory traversa]` 

这里还有个favicon的配置, favicon支持mmh3或md5, 可以配置多条。

需要注意的是`favicon`与`send_data`字段都只用在命令行开启了`-v`(主动指纹识别)模式下才会生效。每个指纹只要命中了一条规则就会退出, 不会做重复无效匹配。

### Service指纹

上面的指纹都没有填写protocol , 所以默认是http指纹. fingers还支持service指纹, 规则与http指纹完全一致. 只需要将protocol设置为tcp/udp即可.

以这个rdp服务为例学习如何编写一个tcp指纹.

```
- name: rdp
  default_port:
    - rdp
  protocol: tcp
  rule:
    - regexps:
        regexp:
          - "^\x03\0\0"
      send_data: b64de|AwAAKiXgAAAAAABDb29raWU6IG1zdHNoYXNoPW5tYXANCgEACAADAAAA
```

指纹的`default_port`可以使用port.yaml中的配置.

port.yaml中的rdp:

```
- name: rdp
  ports:
    - '3389'
    - '13389'
    - '33899'
    - "33389"
```



另外, rdp服务需要主动发包才能获取到待匹配的数据, 因此, 还需要配置send_data. 

而为了方便在yaml中配置二进制的发包数据, gogo添加了一些简单的编码器. 分别为:

* b64en , base64编码
* b64de , base64解码
* hex, hex编码
* unhex, hex解码
* md5, 计算md5

在数据的开头添加`b64de|` 即可生效. 如果没有添加任何装饰器, 数据将以原样发送. 需要注意的是yaml解析后的二进制数据可能不是你看到的, **强烈建议二进制数据都使用base64或hex编码后使用**.