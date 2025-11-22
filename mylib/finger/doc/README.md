# overview

repo: https://github.com/chainreactors/fingers

fingers 是用来各种指纹规则库的go实现, 不同规则库的语法不同, 为了支持在工具多规则库. 于是新增了fingers仓库管理各种不同的规则引擎, 允许不同的输入结构, 但统一输出结构. 并合并输出结果, 最大化指纹识别能力

目前fingers仓库已经成为[spray](https://github.com/chainreactors/spray) 与 [gogo](https://github.com/chainreactors/gogo)的指纹引擎.  后续将移植到更多工具中, 也欢迎其他工具使用本仓库. 

## Features

### 指纹库

fingers engine 通过实现多个指纹库的解析, 实现一次扫描多个指纹库匹配。最大程度提升指纹能力

#### fingers

fingers原生支持的指纹库, 也是目前支持最多特性的指纹库

!!! example "Features."
    *  支持多种方式规则配置
        *  支持多种方式的版本号匹配
        *  404/favicon/waf/cdn/供应链指纹识别
        *  主动指纹识别
        *  超强性能, 采用了缓存,正则预编译,默认端口,优先级等等算法提高引擎性能
        *  重点指纹,指纹来源与tag标记

具体语法请见 #DSL

#### wappalyzer

https://github.com/chainreactors/fingers/tree/master/wappalyzer 为wappalyzer指纹库的实现, 核心代码fork自 https://github.com/projectdiscovery/wappalyzergo , 将其输出结果统一为frameworks.

后续将会提供每周更新的github action, 规则库只做同步. 

#### fingerprinthub

规则库本体位于: https://github.com/0x727/FingerprintHub

https://github.com/chainreactors/fingers/tree/master/fingerprinthub 为其规则库的go实现. 本仓库的此规则库只做同步.

后续将会提供每周更新的github action, 规则库只做同步. 

#### ehole

规则库本体位于: https://github.com/EdgeSecurityTeam/EHole

https://github.com/chainreactors/fingers/tree/master/ehole 为其规则库的go实现. 本仓库的此规则库只做同步.

#### goby

规则库本体来自开源社区的逆向[goby](https://gobies.org/) Thanks @XiaoliChan @9bie .

https://github.com/chainreactors/fingers/tree/master/goby 为其规则库的go实现. 本仓库的此规则库只做同步.
