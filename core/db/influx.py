#!/usr/bin/env python
# -*- coding:utf-8 -*-
# __author__ = Lyon


from core.app import config
from influxdb import InfluxDBClient


class Influx(InfluxDBClient):
    pass


influx = Influx(**config.influx_config)
