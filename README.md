[![GPL 3.0 license](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://github.com/Filterrr/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL%203.0)
[![CC BY-NC-SA 4.0 license](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://github.com/Filterrr/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA%204.0)
<!-- 居中的大标题 -->
<h1 align="center" style="font-size: 70px; margin-bottom: 20px;">AdBlock_Rule_For_Clash</h1>

<!-- 居中的副标题 -->
<h2 align="center" style="font-size: 30px; margin-bottom: 40px;">适用于Clash（mihomo核心）的广告域名拦截RULE-SET规则集，每天更新一次</h2>

<!-- 徽章（根据需要调整） -->
<p align="center" style="margin-bottom: 40px;">
    <img src="https://img.shields.io/badge/last%20commit-today-brightgreen" alt="last commit" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/forks/Filterrr/AdBlock_Rule_For_Clash" alt="forks" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/stars/Filterrr/AdBlock_Rule_For_Clash" alt="stars" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/issues/Filterrr/AdBlock_Rule_For_Clash" alt="issues" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/license/Filterrr/AdBlock_Rule_For_Clash" alt="license" style="margin-right: 10px;">
</p>

<br>
<br>
<table border="1" style="border-collapse: collapse; width: 100%; font-family: Arial, sans-serif;">
  <tr>
    <td colspan="2" style="background-color: #f2f2f2; font-weight: bold; text-align: center; padding: 10px;">订阅地址</td>
  </tr>
  <tr>
    <td style="padding: 8px;">YAML</td>
    <td style="padding: 8px;">
      <strong><a href="https://raw.githubusercontent.com/Filterrr/AdBlock_Rule_For_Clash/main/adblock_reject.yaml" style="color: #0066cc;">Github原始链接</a></strong>| 
      <strong><a style="padding: 8px;">YAML</a></strong>
    </td>
  </tr>
  <tr>
    <td style="padding: 8px;">MRS</td>
    <td style="padding: 8px;">
      <strong><a href="https://raw.githubusercontent.com/Filterrr/AdBlock_Rule_For_Clash/main/adblock_reject.mrs" style="color: #0066cc;">Github原始链接</a></strong>
    </td>
  </tr>
  <tr>
    <td style="padding: 8px;">TXT</td>
    <td style="padding: 8px;">
      <strong><a href="https://raw.githubusercontent.com/Filterrr/AdBlock_Rule_For_Clash/main/adblock_reject.txt" style="color: #0066cc;">Github原始链接</a></strong>
    </td>
  </tr>
</table>


<hr>

## 警告:本过滤器订阅有可能破坏某些网站的功能，也有可能封禁某些色情、赌博网站，使用前请斟酌考虑，如有误杀请积极issue反馈。

<hr>

### **关于本仓库使用方式：**

  #### *使用方式：将下面对应格式的配置文件中rule-providers字段和rules字段内容添加到你的配置文件充当远程规则集，需要特别注意配置文件的缩进和对齐（同步本仓库的云端部署的远程规则集配置)*
<hr>

```conf
#DNS模块拦截
dns:
  enable: true
  nameserver-policy:
    'rule-set:adblock': rcode://success
```


```conf
#YAML格式外部远程拦截域名规则集
rule-providers:
  adblock:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/Filterrr/AdBlock_Rule_For_Clash/main/adblock_reject.yaml
    path: ./ruleset/adblock_reject.yaml
    interval: 120
    
rules:
  - RULE-SET,adblock,REJECT
```

```conf
#MRS格式外部远程拦截域名规则集
rule-providers:
  adblock:
    type: http
    behavior: domain
    format: mrs
    url: https://raw.githubusercontent.com/Filterrr/AdBlock_Rule_For_Clash/main/adblock_reject.mrs
    path: ./ruleset/adblock_reject.mrs
    interval: 120
    
rules:
  - RULE-SET,adblock,REJECT
```

```conf
#TEXT格式外部远程拦截域名规则集
rule-providers:
  adblock:
    type: http
    behavior: domain
    format: txt
    url: https://raw.githubusercontent.com/Filterrr/AdBlock_Rule_For_Clash/main/adblock_reject.txt
    path: ./ruleset/adblock_reject.txt
    interval: 120
    
rules:
  - RULE-SET,adblock,REJECT
```




<hr>

**关于本仓库的使用效果为什么没有普通广告过滤器效果好的疑问解答：**
<br>
*因为普通的广告过滤器包含域名过滤（拦截广告域名）、路径过滤（例如拦截URL路径中包含/ads/的所有请求）、正则表达式过滤（例如拦截所有包含ads.js或ad.js的URL）、类型过滤（例如只拦截图片资源）、隐藏元素等等多因素作用下使得在广告拦截测试网站中可以取得高分。**但碍于clash的路由行为（可参考相关文档）**，本仓库仅提取了被拦截域名进行域名匹配过滤，换言之，本仓库就是一个“删减版”的广告过滤器（仅保留了域名匹配过滤功能，规则数在**10万**条左右），所以最终效果没有广告过滤器效果好*
<br>
<br>



**特别鸣谢**

1. [mihomo](https://github.com/MetaCubeX/mihomo)
2. [Adguard](https://github.com/AdguardTeam/AdGuardFilters)
3. [REIJI007](https://github.com/REIJI007/AdBlock_Rule_For_Clash)
4. [217heidai](https://github.com/217heidai/adblockfilters)


## LICENSE
- [CC-BY-SA-4.0 License](https://github.com/Filterrr/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA%204.0)
- [GPL-3.0 License](https://github.com/Filterrr/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL%203.0)



