#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import time
import tempfile

from pymongo import MongoClient
import gridfs

try:
    import magic
except ImportError:
    pass

from utils import get_file, clean_data, get_type, Config

JOBNAME = 'FILEMAGIC'
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
            enumerate(db.fs.files.find({'filetype': {'$exists': False}},
                      timeout=False)):
            try:
                logger.info('[%s] Processing sample %s' % (sampleno,
                            sample['sha256']))
                samplekey = {'sha256': sample['sha256']}

                # download sample file

                logger.debug('[%s] Downloading data' % sampleno)
                data = get_file(db, sha256=sample['sha256'])

                # Do analysis

                logger.debug('[%s] Analysing' % sampleno)
                file_type = clean_data(get_type(data))

                # Store results

                logger.debug('[%s] Storing results into MongoDB'
                             % sampleno)
                if file_type:
                    db.fs.files.update(samplekey,
                            {'$set': {'filetype': file_type}},
                            upsert=True)

                # delete sample file

                logger.debug('[%s] Deleting temporary data' % sampleno)
                del samplekey
                del data

                logger.info('[%s] Metadata updated' % sampleno)
            except Exception, e:
                logger.exception(e)
                pass
    except Exception, e:

        logger.exception(e)
        pass

    logger.info('Sleeping %s minutes' % SLEEPTIME)
    time.sleep(SLEEPTIME * 60)

