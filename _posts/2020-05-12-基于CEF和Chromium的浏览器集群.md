## 背景

在JS动态加载越来越被广泛应用的现在，想要打造通用的爬虫系统离不开强大的浏览器集群。市面上有诸多关于selenium和puppeteer操纵浏览器进行爬取的教程。但是随着反爬的深入，selenium的特征很容易被检测，这里有一些相关的讨论：[Can a website detect when you are using selenium with chromedriver?
](https://stackoverflow.com/questions/33225947/can-a-website-detect-when-you-are-using-selenium-with-chromedriver)。除了自动化测试流派，是否还有其他操纵浏览器的方式呢？本文提出的是基于CEF（Chromium Embedded Framework）和Chromium，定制一套专业的爬虫浏览器环境，并工程化为浏览器集群。

## Chromium

## CEF

CEF是支持在其他应用中嵌入Chromium浏览器的框架，提供了丰富的接口以操纵浏览器。

### 编译

## 浏览器集群

## 总结