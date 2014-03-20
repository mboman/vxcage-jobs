#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import os
import time

from pymongo import MongoClient
import gridfs
import hashlib
import pydeep

from utils import get_file, Config

JOBNAME = 'BASENAME'
SLEEPTIME = 1

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

while True:
    try:
        for (sampleno, sample) in enumerate(db.fs.files.find({'filename': {'$regex': '.*/.*' }})):
            try:
                logger.info('[%s] Processing sample %s' % (sampleno, sample['md5']))
                key = {'md5': sample['md5']}

                logger.debug('[%s] Old name: %s' % (sampleno, sample['filename']))
                newfilename = os.path.basename(sample['filename'])
                logger.debug('[%s] New name: %s' % (sampleno, newfilename))

                logger.debug('[%s] Storing results into MongoDB' % sampleno)

                db.fs.files.update(key, {'$set': {'filename': newfilename}}, upsert=True)

                logger.debug('[%s] Removing temporary data' % sampleno)
                del key

                logger.info('[%s] Metadata updated' % sampleno)
            except Exception, e:
                logger.exception(e)
                pass
    except Exception, e:

        logger.exception(e)
        pass

    logger.info('Sleeping %s minutes' % SLEEPTIME)
    time.sleep(SLEEPTIME * 60)

