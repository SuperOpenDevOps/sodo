#!/usr/bin/env python
# -*- coding:utf-8 -*-
# __author__ = Lyon

"""
Mongoengine Doccument : http://docs.mongoengine.org/
Motor for Tornado Document : https://motor.readatetime.datetimehedocs.io/en/stable/tutorial-tornado.html
Motor for query : https://motor.readatetime.datetimehedocs.io/en/stable/api-tornado/motor_collection.html#motor.motor_tornado.MotorCollection
"""

import re
import datetime
from core.app import config
from urllib.parse import quote_plus
from mongoengine import Document, fields, connect
from motor.core import AgnosticCollection
from motor.motor_tornado import MotorClient
from motor.metaprogramming import create_class_with_framework

# Sync link
"""
connect(config.mongo_config["db"],
        host=config.mongo_config['host'],
        port=config.mongo_config["port"],
        username=config.mongo_config["username"],
        password=config.mongo_config["password"],
        maxPoolSize=config.mongo_config['max_connections'],
        minPoolSize=config.mongo_config['min_connections'],
        connect=False)

# Async link
client = MotorClient(
    host=config.mongo_config['host'],
    port=config.mongo_config['port'],
    username=config.mongo_config['username'],
    password=config.mongo_config['password'],
    maxPoolSize=config.mongo_config['max_connections'],
    minPoolSize=config.mongo_config['min_connections'],
    authSource=config.mongo_config['db'],
    authMechanism='SCRAM-SHA-1'
)
"""
mongo_config = config.mongo_config
mongo_config['username'] = quote_plus(mongo_config['username'])
mongo_config['password'] = quote_plus(mongo_config['password'])

if config.env != 'pro':
    client = MotorClient(
        "mongodb://{username}:{password}@{host}:{port}/{db}?maxPoolSize={max_connections}".format(
            **mongo_config)
    )
    connect(host="mongodb://{username}:{password}@{host}:{port}/{db}?maxPoolSize={max_connections}".format(
            **mongo_config))
else:
    # replica set 高可用连接方式
    client = MotorClient(
        "mongodb://{username}:{password}@{host}:{port},{host2}:{port2}/{db}?replicaSet={replicaSet}&maxPoolSize={max_connections}".format(
            **mongo_config)
    )
    connect(host="mongodb://{username}:{password}@{host}:{port},{host2}:{port2}/{db}?replicaSet={replicaSet}&maxPoolSize={max_connections}".format(
            **mongo_config))

mongo_db = client[config.mongo_config['db']]

HUMP_REGEX = re.compile(r'([a-z]|\d)([A-Z])')


class Collection(AgnosticCollection):
    """AgnosticCollection Object Descriptor."""

    def __init__(self):
        pass

    def __get__(self, instance, owner):
        collection_class = create_class_with_framework(
            AgnosticCollection, owner.database._framework, owner.database.__module__)
        return collection_class(owner.database, owner.collection_name())


class MongoModel(Document):
    DELETE_NO = 0
    DELETE_IS = 1

    # async collection
    database = mongo_db

    is_delete = fields.IntField(verbose_name='删除状态', default=DELETE_NO)
    create_time = fields.DateTimeField(verbose_name='创建时间', default=datetime.datetime.now)
    update_time = fields.DateTimeField(verbose_name='更新时间', default=datetime.datetime.now)

    # sync objects
    # type: Document._meta.objects

    # async objects
    query = Collection()

    meta = {
        'abstract': True
    }

    def __init__(self, *args, **kwargs):
        _id = None
        if '_id' in kwargs:
            _id = kwargs.pop('_id')
        super(MongoModel, self).__init__(*args, **kwargs)

    @classmethod
    def collection_name(cls):
        return cls._meta.get('collection', re.sub(HUMP_REGEX, r'\1_\2', cls.__name__))

    @classmethod
    async def async_create(cls, *items, **values):
        """
        Async create
        :param items: call `insert_many`
        :param values: call `insert_one`
        :return:
            items -> list[id] or None
            values -> Document object or None
        """
        if items:
            result = await cls.query.insert_many([cls(**i).to_mongo() for i in items])
            try:
                return result.inserted_ids
            except:
                return None

        if values:
            document = cls(**values)
            result = await cls.query.insert_one(document.to_mongo())
            try:
                document.pk = result.inserted_id
                document._id = result.inserted_id
                return document
            except:
                return None

    async def async_replace(self):
        assert (self.pk or self._id), "%s object's `_id` or `pk` cannot be None." % self.__class__.__name__
        return await self.__class__.query.replace_one({'_id': self.pk or self._id}, self.to_mongo())

    async def async_update(self, **kwargs):
        assert (self.pk or self._id), "%s object's `_id` or `pk` cannot be None." % self.__class__.__name__
        return await self.__class__.query.update_one({'_id': self.pk or self._id}, {'$set': kwargs})

    @classmethod
    async def async_update_many(cls, filter, update):
        """
            print('matched %d, modified %d' %
          (result.matched_count, result.modified_count))
        :param filter:
        :param update:
        :return:
        """
        return await cls.query.update_many(filter, update)

    async def async_delete(self, *args, **kwargs):
        return await self.async_update(is_delete=self.DELETE_IS)

    @classmethod
    async def async_get(cls, match, **kwargs):
        return await cls.query.find_one(match, **kwargs)

    @classmethod
    async def async_count(cls, match, **kwargs):
        return await cls.query.count_documents(match, **kwargs)

    @classmethod
    def sync_create(cls, **kwargs):
        document = cls(**kwargs)
        return super(MongoModel, document).save(**kwargs)

    def sync_delete(self):
        """Override Document.delete"""
        return self.sync_update(is_delete=self.DELETE_IS)

    def sync_update(self, **kwargs):
        if not kwargs.get('update_time'):
            kwargs['update_time'] = datetime.datetime.now()
        super(MongoModel, self).update(**kwargs)
        return self

    def __str__(self):
        return "%s object [%s]" % (self.__class__.__name__, self.pk or self._id)
