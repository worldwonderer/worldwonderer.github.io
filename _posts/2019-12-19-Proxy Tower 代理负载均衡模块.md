## 起源
很多人会有疑问，Github上已有众多优秀的代理池项目了，如proxy_pool，haiproxy等。为什么还要造这个轮子呢？

遇到的问题：

* 这些项目采集来的代理IP虽然已经过了一层筛选，但成功率还是不高。
* 用起来比较繁琐，还是需要写一些轮换的逻辑。
* 没有对代理结果是否有效做校验，无法甄别一些广告或失效代理。

[Proxy Tower](https://github.com/worldwonderer/proxy_tower) 就是为了解决这些问题而生的。

## 特性

采集来的免费代理IP，谁也不知道下一秒还能不能用。思考良久后，决定祭出暴力美学，**1个代理IP没成功，一次来10个总该有个成功的吧**？

Proxy Tower的并发逻辑由Python3 asyncio实现，支持将收到的代理请求转发给**多个proxy**，返回**最快**并且**有效**的response。

经测试，将并发转发数调至5，代理成功率显著提高；当并发数调到变态的10时，成功率接近100%。当然我不建议调这么高，这会影响该代理IP的其他使用者。

采集完代理IP之后存哪？怎么用，客户端还是API？失效了怎么轮换？开箱即用，可不可以。Proxy Tower本身就是一个代理服务器，使用只需要一行。`curl -x "http://0.0.0.0:8893" "http://movie.douban.com"`

但用着用着又发现两个问题：

* 有几个代理IP速度非常快，但是返回的都是一个毫不相关的广告页面。
* 或者有时候发现有几个代理IP被封了，但还一直在使用。

只能对代理IP返回的结果做校验吧，问题又来了，每个站点肯定都不一样啊，不急这也帮你做好了。Proxy Tower中有个**Pattern**类。pattern是目标站点的某个复用页面，通常有同样的URL前缀，类似的HTML结构，如豆瓣电影`movie.douban.com/subject/`。

通过前缀树存储pattern，这样在抓取类似`https://movie.douban.com/subject/27119724/`的链接，就会匹配到对应的pattern。我们可以对pattern，设置一个校验规则，如关键词`ratingValue`（豆瓣评分），或者一个Xpath`//*[@id="recommendations"]/h2/i`，Proxy Tower就会根据指定的规则校验，并对代理IP计分。

另外因为已经有了众多优秀的代理池项目，Proxy Tower没有接入爬取代理IP的功能。项目中已经配置了通过proxy_pool的API，项目启动的时候会获取一次，在此特别感谢proxy_pool的作者。大家可以在models/proxy.py中拓展代理IP源，目前支持文件和API两种方式。

```python
# 文件
class ProxyFile(ProxySource):

    def __init__(self, tag, file_path):
        self.file_path = file_path
        self.tag = tag

    async def fetch_proxies(self):
        with open(self.file_path, 'r') as f:
            proxy_candidates = re.findall(self.proxy_pattern, f.read())
            for proxy in proxy_candidates:
                yield Proxy.parse(proxy, tag=self.tag, support_https=True, paid=False)


# API
class ProxyApi(ProxySource):

    def __init__(self, tag, api, valid_time):
        self.api = api
        self.tag = tag
        self.valid_time = valid_time

    async def fetch_proxies(self):
        r = await crawl("GET", self.api)
        text = await r.text()
        proxy_candidates = re.findall(self.proxy_pattern, text)
        for proxy in proxy_candidates:
            yield Proxy.parse(proxy, tag=self.tag, valid_time=self.valid_time, paid=False)
```

由于每个代理源获取到的代理IP特性不同，可以使用tag给代理IP做标记，并初始化属性。

* valid_time：代理IP有效时长。
* support_https：代理IP是否支持https。
* paid: 代理IP是否为付费代理。

另外，对于必须使用https的站点，可以在请求的headers中添加`'Need-Https': 'yes'`，Proxy Tower会选取带有support_https标记的代理IP。注：URL不要带上https，例如使用`http://www.bilibili.com`，而不是`https://www.bilibili.com`。

Proxy Tower还提供了一个[Dashboard](https://github.com/worldwonderer/proxy_tower_dashboard)，支持：

* 查看proxy。
* 查看、修改、添加pattern。
* 各pattern成功率的折线表。


## 结语
如果[Proxy Tower](https://github.com/worldwonderer/proxy_tower) 能解决你的部分问题，欢迎Star，这对我很重要。
