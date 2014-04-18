#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import time

from pymongo import MongoClient
import gridfs
import yara

from utils import get_file, clean_data, Config

JOBNAME = 'YARA'
SLEEPTIME = 1

# create logger

logger = logging.getLogger(JOBNAME)
logger.setLevel(logging.DEBUG)

# create console handler with a higher log level

logch = logging.StreamHandler()
logch.setLevel(logging.DEBUG)

# create formatter and add it to the handlers

formatter = \
    logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                      )
logch.setFormatter(formatter)

# add the handlers to the logger

logger.addHandler(logch)

client = MongoClient(host=Config().database.dbhost, port=Config().database.dbport)
db = client.vxcage
fs = gridfs.GridFS(db)

rules = yara.compile(filepath=Config().yara.rulefile)


def filter_non_printable(str):
    return ''.join([c for c in str if ord(c) > 31 or ord(c) == 9])


def str2hex(s):
    return ''.join('{0:x}'.format(ord(c)) for c in s)


def mycallback(data):
    global metadata
    if data['matches']:
        for (index, strng) in enumerate(data['strings']):
            data['strings'][index] = (data['strings'][index][0],
                    filter_non_printable(data['strings'][index][1]),
                    str2hex(data['strings'][index][2]))
        logger.debug('YARA Rules matched: %s' % data)
        metadata.append(data)
    yara.CALLBACK_CONTINUE


while True:
    for (sampleno, sample) in \
        enumerate(db.fs.files.find({'yara': {'$exists': False}},
                  timeout=False)):
        try:
            logger.info('[%s] Processing sample %s' % (sampleno,
                        sample['sha256']))
            sample_key = {'_id': sample['_id']}
            job_key = {'md5': sample['md5']}

            metadata = []

            # download sample file

            logger.debug('[%s] Downloading data' % sampleno)
            data = get_file(db, sha256=sample['sha256'])

            # Do analysis

            logger.debug('[%s] Analysing' % sampleno)
            matches = rules.match(data=data, callback=mycallback)

            # Store results

            if len(metadata) > 0:
                metadata = clean_data(metadata)
                logger.debug('[%s] Storing results into MongoDB'
                             % sampleno)
                db.fs.files.update(sample_key,
                                   {'$set': {'yara': metadata}},
                                   upsert=True)
                logger.info('[%s] Metadata updated' % sampleno)
        except Exception, e:
            logger.exception(e)
            pass

    logger.info('Sleeping %s minutes' % SLEEPTIME)
    time.sleep(SLEEPTIME * 60)
