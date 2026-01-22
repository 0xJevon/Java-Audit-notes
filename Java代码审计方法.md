# Java代码审计方法

按一条**固定路线**（流程）+ 一套**“在哪、长啥样、怎么验证”**的套路（技巧）来。下面把行业里最常见的“七步流程”和“Top10 审计技巧”直接列给你，拿来就能套。

------------------------------------------------
一、Java 代码审计的 7 步流程（S-T-A-T-I-C 模型，谐音好记）

1. **S**urvey——先扫架构  
   - 看是 Spring Boot / 老 SSM / 自研框架，把 `pom.xml`、`web.xml`、`application.yml` 拉一遍，把依赖库版本、组件（MyBatis/JPA/Shiro/Spring-Security/Fastjson/Jackson…）列成表。  
   - 目的：先知道“哪里可能出洞”，比如看到 Fastjson≤1.2.80 就先把“反序列化”标红。

2. **T**aint——找入口，画“污染源”  
   - 用 IDEA “Find Usages”从  
     `@RequestMapping`、`@GetMapping`、`HttpServlet.service()`、`WebSocket@OnMessage`、`MQ Listener`、`Dubbo Provider`、`XMLRPC`、`QuartzJob` …  
     一路往回跟，把所有“用户能碰得到”的方法标成红色★。  
   - 这一步产出：一张“入口清单”，后面只盯这些★，别的代码先不看。

3. **A**nalyze——跟数据流（人工 + 工具）  
   - 工具：Fortify / CodeQL / Semgrep / SCA 先跑一遍，把“SQLI、XSS、PathTraversal、命令注入”高可信告警导出。  
   - 人工：从★出发，看字符串在方法间怎么传——是否进了拼接 SQL？是否写进 `Runtime.exec()`？是否返回给前端？  
   - 技巧：遇到 MyBatis 只看 `${}` 不看 `#{}`；遇到 JPA 只看 `createNativeQuery` 不看 `findByXXX`。

4. **T**est——把可疑点变成 PoC  
   - 本地把项目跑起来，用 Burp 重放，把单引号、双引号、`\u0000`、`../、${jndi:、<svg/onload=` 打进去，看是否 500、回显、延时。  
   - 能弹计算器/出数据/弹框 就截图写进报告，不能就退回第 3 步。

5. **I**mpact——定级 + 修法  
   - 按公司 SRC 标准给“严重/高危/中危/低危”，并给出修法：参数化、白名单、ESAPI、模板自动转义、文件沙箱、权限校验注解等。  
   -同时把“修了会不会影响业务”写清楚，方便研发排期。

6. **C**omment——落地成报告  
   - 一条漏洞 = 标题 + 位置（类+方法+行号）+ 描述 + 危害 + PoC + 修复建议 + 关键代码截图。  
   - 用 markdown/Confluence/飞书妙记 都行，重点是研发能一键定位。

7. **C**heck——回头看修复  
   - 研发提交 `fix: xxx` PR 后，把补丁拉下来再跑一遍第 3、4 步，确认“真的修了、没修歪、没引入新洞”再关闭工单。

------------------------------------------------
二、10 个“高频且高危害”的审计技巧（套路）

| 漏洞类型            | 搜索关键词/正则                                              | 快速判断技巧                                                 | 典型 payload 验证                                            |
| ------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 1. SQL 注入         | `createStatement\(\)`<br>`createNativeQuery\(`<br>`${`       | MyBatis 看 `${}`、JPA 看 `@Query("...+ "+xxx)`               | `'+or+1=1--`                                                 |
| 2. MyBatis 顺序注入 | `order by ${sort}`<br>`like '%${name}%'`                     | 字段名/排序字段常被漏掉                                      | `id+desc,sleep(3)`                                           |
| 3. XSS              | `model.addAttribute("x", userInput)`<br>`return userInput`   | 看最后是否进 Thymeleaf `${}` 或 Vue 双花括号                 | `"><svg/onload=alert(1)>`                                    |
| 4. SpEL 注入        | `@Value("#{`")`<br>`parser.parseExpression(` | 用户可控字符串拼进 `#{}` | `T(java.lang.Runtime).exec("calc")` |                                                              |                                                              |
| 5. 反序列化         | `readObject()`<br>`Jackson enableDefaultTyping`<br>`Fastjson<=1.2.80` | 黑名单若没封 `L;`/`[` 仍可打                                 | `{"@type":"java.net.InetAddress","val":"dnslog"}`            |
| 6. 命令注入         | `Runtime.getRuntime().exec(`<br>`ProcessBuilder`             | 看拼接部分是否含空格、是否用 `StringTokenizer`               | `127.0.0.1%0acalc`                                           |
| 7. 路径穿越         | `new File(basePath, fileName)`<br>`Paths.get(root, path)`    | 是否 `getCanonicalPath` 再校验                               | `../../../etc/passwd`                                        |
| 8. XXE              | `DocumentBuilderFactory dbf = ...;`<br>`SAXParser`           | 看 `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` 有没有 | `<!DOCTYPE x [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>` |
| 9. 权限绕过         | `@PreAuthorize("hasRole('ADMIN')")` 缺失<br>`shiro.ini` 里 `/** = authc` 漏写 | 直接访问 `/admin;/index` 或 `/admin/../admin`                | `/admin;/user/list`                                          |
| 10. JWT 弱密钥      | `Jwts.parserBuilder().setSigningKey(secret)`                 | 看 secret 是否硬编码、长度<256 bit                           | 用 jwt_tool 爆破或直接改 `alg=none`                          |

------------------------------------------------
三、落地小结

1. 先跑工具 → 拿到“可疑点列表”  
2. 用入口清单过滤 → 只盯用户可控链路  
3. 按上表 10 条技巧逐条对关键词“人工复核 + PoC”  
4. 能复现的写报告、给修复、再回归验证  

把这套“七步流程 + 十类技巧”做成 checklist，下次拿到任何 Java 源码或反编译 jar，直接按表打钩，就能在 1~2 天内输出一份研发愿意认、SRC 愿意收的高质量审计报告。