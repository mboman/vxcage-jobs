#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
from pymongo import MongoClient
import os
import gridfs
from utils import get_file, Config
import time

import string

from pprint import pprint

JOBNAME = 'STRINGS'

# create logger

logger = logging.getLogger(JOBNAME)
logger.setLevel(logging.DEBUG)

# create console handler with a higher log level

logch = logging.StreamHandler()
logch.setLevel(logging.DEBUG)

# create formatter and add it to the handlers

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logch.setFormatter(formatter)

# add the handlers to the logger

logger.addHandler(logch)

client = MongoClient(host=Config().job.dbhost, port=Config().job.dbport)
db = client.vxcage
fs = gridfs.GridFS(db)


def strings(filedata, min=4):
    result = ''
    for c in filedata:
        if c in string.printable:
            result += c
            continue
        if len(result) >= min:
            yield result
        result = ''


while True:
    try:
        for (sampleno, sample) in enumerate(db.fs.files.find({'strings': {'$exists': False}})):
            try:
                logger.info('[%s] Processing sample %s' % (sampleno, sample['sha256']))
                key = {'sha256': sample['sha256']}

                logger.debug('[%s] Downloading data' % sampleno)
                data = get_file(db, sha256=sample)

                # Do analysis

                logger.debug('[%s] Analysing' % sampleno)
                stringdata = strings(data)
                pprint(list(strings(data)))

                # Store results

                logger.debug('Storing results into MongoDB')

                # db.fs.files.update(key, {"$set" : {'strings' : stringdata}}, upsert=True)

                logger.debug('Removing temporary data')
                del key
                del data
                del stringdata

                logger.info('Metadata updated')
            except Exception, e:
                logger.exception(e)
                pass
    except Exception, e:

        logger.exception(e)
        pass

    logger.info('Sleeping %s minutes' % SLEEPTIME)
    time.sleep(SLEEPTIME * 60)

