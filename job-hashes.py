#!/usr/bin/python
# -*- coding: utf-8 -*-

import hashlib
import logging
import time

from pymongo import MongoClient
import gridfs
import pydeep

from utils import get_file, Config

JOBNAME = 'HASHES'
SLEEPTIME = 1

# create logger

logger = logging.getLogger(JOBNAME)
logger.setLevel(logging.DEBUG)

# create console handler with a higher log level

logch = logging.StreamHandler()
logch.setLevel(logging.INFO)

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

while True:
    try:
        for (sampleno, sample) in \
            enumerate(db.fs.files.find({'sha1': {'$exists': False}},
                      timeout=False)):
            try:
                logger.info('[%s] Processing sample %s' % (sampleno,
                            sample['md5']))
                key = {'md5': sample['md5']}

                metadata = {}
                logger.debug('[%s] Downloading data' % sampleno)
                data = get_file(db, md5=sample['md5'])

                # Do analysis

                logger.debug('[%s] Analysing' % sampleno)

                # metadata['md5'] = hashlib.md5(data).hexdigest()

                metadata['sha1'] = hashlib.sha1(data).hexdigest()
                metadata['sha256'] = hashlib.sha256(data).hexdigest()
                metadata['sha512'] = hashlib.sha512(data).hexdigest()
                metadata['ssdeep'] = pydeep.hash_buf(data)

                # Store results

                logger.debug('[%s] Storing results into MongoDB'
                             % sampleno)
                for (metakey, metaval) in metadata.iteritems():
                    db.fs.files.update(key,
                            {'$set': {metakey: metaval}}, upsert=True)

                logger.debug('[%s] Removing temporary data' % sampleno)
                del key
                del metadata
                del data

                logger.info('[%s] Metadata updated' % sampleno)
            except Exception, e:
                logger.exception(e)
    except Exception, e:

        logger.exception(e)

    logger.info('Sleeping %s minutes' % SLEEPTIME)
    time.sleep(SLEEPTIME * 60)

