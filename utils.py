#!/usr/bin/python
# -*- coding: utf-8 -*-

import ConfigParser
import StringIO
import json
import logging
import string

from pymongo import MongoClient
import gridfs


class Dictionary(dict):

    def __getattr__(self, key):
        return self.get(key, None)

    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class Config:

    def __init__(self, cfg='job.conf'):
        config = ConfigParser.ConfigParser()
        config.read(cfg)

        for section in config.sections():
            setattr(self, section, Dictionary())
            for (name, raw_value) in config.items(section):
                try:
                    value = config.getboolean(section, name)
                except ValueError:
                    try:
                        value = config.getint(section, name)
                    except ValueError:
                        value = config.get(section, name)

                setattr(getattr(self, section), name, value)

    def get(self, section):
        try:
            return getattr(self, section)
        except AttributeError, e:
            return None


def clean_data(obj):
    ''' Remove/Replace all characters that doesn't work with MongoDB '''

    clean = lambda dirty: ''.join(filter(string.printable.__contains__,
                                  dirty))

    if isinstance(obj, str):
        obj = clean(obj)
    elif isinstance(obj, list):
        for (index, entry) in enumerate(obj):
            obj[index] = clean_data(obj[index])
    else:
        for key in obj.keys():
            if isinstance(obj[key], dict):

                # Run the function recursively

                obj[key] = clean_data(obj[key])

            if isinstance(obj[key], str):
                value = obj[key]

                # logging.debug("Removing all non-printable characters from string")

                value = clean(value)
                obj[key] = unicode(value)  # Make sure the value is in unicode format

            new_key = key.replace('.', '_')  # Replace dots with underscore
            new_key = new_key.replace('$', '_')  # Replace dollar signs with underscore
            new_key = clean(new_key)  # Only allow printable characters
            if new_key != key:
                obj[new_key] = obj[key]
                del obj[key]
    return obj


def get_file(
    db,
    md5=None,
    sha1=None,
    sha256=None,
    sha512=None,
    ):
    ''' Retrieves a file from GridFS and returns it as a byte-stream
    @md5: md5 hash of the file to retreive
    @sha1: sha1 hash of the file to retreive
    @sha256: sha256 hash of the file to retreive
    @sha512: shs512 hash of the file to retreive
    @returns the file content as a binary string
    '''

    fs = gridfs.GridFS(db)
    _id = None
    result = None

    if md5:
        result = db.fs.files.find_one({'md5': md5})
    elif sha1:
        result = db.fs.files.find_one({'sha1': sha1})
    elif sha256:
        result = db.fs.files.find_one({'sha256': sha256})
    elif sha512:
        result = db.fs.files.find_one({'sha512': sha512})

    if result:
        _id = result['_id']
        if _id:
            fh = fs.get(_id)
            if fh:
                return fh.read()
    return None


def del_file(
    db,
    md5=None,
    sha1=None,
    sha256=None,
    sha512=None,
    ):
    ''' Retrieves a file from GridFS and returns it as a byte-stream
    @md5: md5 hash of the file to retreive
    @sha1: sha1 hash of the file to retreive
    @sha256: sha256 hash of the file to retreive
    @sha512: shs512 hash of the file to retreive
    @returns the file content as a binary string
    '''

    fs = gridfs.GridFS(db)
    _id = None
    result = None

    if md5:
        result = db.fs.files.find_one({'md5': md5})
    elif sha1:
        result = db.fs.files.find_one({'sha1': sha1})
    elif sha256:
        result = db.fs.files.find_one({'sha256': sha256})
    elif sha512:
        result = db.fs.files.find_one({'sha512': sha512})

    if result:
        _id = result['_id']
        if _id:
            return fs.delete(_id)
    return None


