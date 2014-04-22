#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
Copyright (c) 2012, Claudio "nex" Guarnieri
Copyright (c) 2013, Michael Boman <michael@michaelboman.org>

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

import ConfigParser
import StringIO
import json
import logging
import string
import os

try:
    from pymongo import MongoClient
    import gridfs
except ImportError:
    sys.exit('ERROR: pymongo library is missing')

FILE_CHUNK_SIZE = 16 * 1024


class Dictionary(dict):

    def __getattr__(self, key):
        return self.get(key, None)

    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class Config:

    def __init__(self, cfg=os.path.join(os.path.dirname(os.path.realpath(__file__)),'vxcage.conf')):
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


logging.basicConfig(format='%(levelname) -10s %(asctime)s %(message)s',
                    level=logging.DEBUG)

def get_type(file_data):
    try:
        ms = magic.open(magic.MAGIC_NONE)
        ms.load()
        file_type = ms.buffer(file_data)
        logging.debug('Got magic through method #1')
    except:
        try:
            file_type = magic.from_buffer(file_data)
            logging.debug('Got magic through method #2')
        except:
            try:
                import subprocess
                file_path = tempfile.NamedTemporaryFile(mode='w+b')
                file_path.write(file_data)
                file_path.flush()
                file_process = subprocess.Popen(['file', '-b',
                        file_path], stdout=subprocess.PIPE)
                file_type = file_process.stdout.read().strip()
                file_path.close()
                logging.debug('Got magic through method #3')
            except:
                return None

    return file_type


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


def put_file(
    gfs,
    sampleData,
    **kwargs
    ):
    ''' Stores a byte-steam into GridFS
    @sha512: shs512 hash of the file to retreive
    @returns the file content as a binary string
    '''

    try:
        new = gfs.new_file(*kwargs)
        for chunk in get_chunks(sampleData):
            logging.debug('writing chunk')
            new.write(chunk)
    finally:
        new.close()
    return True

def get_file(
    db,
    filename=None,
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
                if filename:
                    lfh = open(filename, 'wb')
                    for chunk in fh.read(size=fh.chunk_size):
                        lfh.write(chunk)
                    lfh.close()
                    return filename
                else:
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


def get_chunks(data):
    """Read file contents in chunks (generator)."""

    fd = StringIO.StringIO(data)
    while True:
        chunk = fd.read(FILE_CHUNK_SIZE)
        if not chunk:
            break
        yield chunk
    fd.close()


def jsonize(data):
    return json.dumps(data, sort_keys=False, indent=4)


