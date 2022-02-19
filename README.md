# README

![tornado](https://www.tornadoweb.org/en/stable/_images/tornado.png)

## TODO

1. 阻塞测试
2. 并发测试
...

## 技术栈

| 架构层     | 所选项                                                       |
| ---------- | ------------------------------------------------------------ |
| HTTP       | [tornado](https://tornado-zh-cn.readthedocs.io/zh_CN/latest/) , [asyncio](https://docs.python.org/zh-cn/3/library/asyncio.html) , [Celery](https://docs.celeryproject.org/en/latest/getting-started/first-steps-with-celery.html#installing-celery) |
| HTTP Proxy | Nginx                                                        |
| Database   | MySQL , [Redis](http://redisdoc.com/index.html) , MongoDB , ElasticSearch |
| Deploy     | [Supervisor](http://supervisord.org/) , [Docker](https://docs.docker.com/engine/reference/builder/) , [Docker-Compose](https://docs.docker.com/compose/reference/overview/) |

## 库

| 项            | 库                                                           |
| ------------- | ------------------------------------------------------------ |
| MySQL         | [peewee](http://docs.peewee-orm.com/en/latest/) (同步) , [peewee-async](https://peewee-async.readthedocs.io/en/latest/index.html) (异步) |
| Redis         | [redis](https://redis-py.readthedocs.io/en/stable/) (同步) , [aioredis](https://aioredis.readthedocs.io/en/v1.3.0/examples.html) (异步) |
| MongoDB       | [mongoengine](http://docs.mongoengine.org/) (同步) , [motor](https://motor.readthedocs.io/en/stable/tutorial-tornado.html) (异步) |
| ElasticSearch | 待补充                                                       |
| wechatpy      | [wechatpy](https://wechatpy.readthedocs.io/zh_CN/stable/) (同步) , 异步待封装|                                                     |


## 开始

### 启动

```bash
$ python run.py
```

```bash
# Linux 后台启动
$ nohup python3 run.py > run.log 2>&1 &
```

### Celery

```bash
# 先启动 Celery Beat
$ celery beat -A celerys.server --loglevel=info

# 后启动 Celery Worker
$ celery worker -A celerys.server --loglevel=info
```


### requirements

先安装 `pipreqs`

```bash
$ pip install pipreqs
```
更新 `requirements.txt`

```bash
$ pipreqs . --force
```