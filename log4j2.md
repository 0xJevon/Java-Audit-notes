source

javax.naming.InitialContext#lookup



sink



source

log4j.error

log4j.info



payload

${jndi:ldap:}



以漏洞挖掘的角度分析链

搜索漏洞执行点lookup-》JndiManager

![image-20260109095430945](C:\Users\85885\AppData\Roaming\Typora\typora-user-images\image-20260109095430945.png)

![image-20260109095442347](C:\Users\85885\AppData\Roaming\Typora\typora-user-images\image-20260109095442347.png)

![image-20260109095451543](C:\Users\85885\AppData\Roaming\Typora\typora-user-images\image-20260109095451543.png)

JndiManager.lookup() = this.context.lookup() = InitialContext.lookup()



完整链子

log4j.error/log4j.info

->MessagePatternConverter.format

->StrSubstitutor.replace

->StrSubstitutor.substitute

->StrSubstitutor.resolveVariable()

->JndiLookup.lookup()

->JndiManager.lookup()

## 链分析

前面是日志的调用过程，logger.info和logger.error最后都会进入`MessagePatternConverter.format`所以直接从这开始跟链

![image-20260109180506243](log4j2/image-20260109180506243.png)

往下走便是为什么payload要带`${`，因为这里有个if判断会`workingBuilder`中`${`之后的内容

![image-20260109180846852](log4j2/image-20260109180846852.png)

可以看到value的值就是payload

![image-20260109181139082](log4j2/image-20260109181139082.png)

然后进入`StrSubstitutor.replace`

![image-20260109181224877](log4j2/image-20260109181224877.png)

接着调用`StrSubstitutor.substitute`

![image-20260109181311178](log4j2/image-20260109181311178.png)

往下走到while循环会获取${}中的内容

