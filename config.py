#!/usr/bin/env python
# -*- coding:utf-8 -*-
# __author__ = Lyon

"""配置会被强制转为小写, 在使用配置时, 通过 config.lower_conf_name 使用"""

from core.conf import Config


# 开发环境
class DevConfig(Config):
    env = 'dev'

    install_handlers = [
        'api.influx'
    ]

    # MySQL
    mysql_config = {
        'max_connections': 30,
        'stale_timeout': 300,
        'host': '',
        'db': '',
        'username': '',
        'password': '',
        'port': 3306
    }

    # Mongodb
    mongo_config = {
        'max_connections': 30,
        'min_connections': 10,
        'host': '',
        'host2': '',
        'port': 3717,
        'port2': 3717,
        'db': '',
        'username': '',
        'password': '',
        'replicaSet': ''
    }

    # Redis
    redis_config = {
        'max_connections': 30,
        'min_connections': 10,
        'host': '',
        'db': 0,
        'password': '',
        'port': 6379
    }

    influx_config = {
        'host': '',
        'port': 8086,
        'use_udp': True,
        'username': '',
        'password': '',
        'database': '',
        'timeout': 1,
        'retries': 1
    }


# 生产环境
class ProConfig(Config):
    env = 'pro'
    debug = False
    data_path = "/data"

    install_handlers = [
        'api.influx'
    ]

    # MySQL
    mysql_config = {
        'max_connections': 30,
        'stale_timeout': 300,
        'host': '',
        'db': '',
        'username': '',
        'password': '',
        'port': 3306
    }

    # Mongodb
    mongo_config = {
        'max_connections': 30,
        'min_connections': 10,
        'host': '',
        'host2': '',
        'port': 3717,
        'port2': 3717,
        'db': '',
        'username': '',
        'password': '',
        'replicaSet': ''
    }

    # Redis
    redis_config = {
        'max_connections': 30,
        'min_connections': 10,
        'host': '',
        'db': 0,
        'password': '',
        'port': 6379
    }

    influx_config = {
        'host': '',
        'port': 8086,
        'use_udp': True,
        'username': '',
        'password': '',
        'database': '',
        'timeout': 1,
        'retries': 1
    }

config_env = {
    'dev': DevConfig,
    'pro': ProConfig,
}
