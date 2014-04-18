#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
from pymongo import MongoClient
import gridfs
from utils import get_file, clean_data, Config
import time
import os

import exiftool
import tempfile

from pprint import pprint

JOBNAME = 'EXIF'
SLEEPTIME = 5

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

uselessexifkey = [
    u'SourceFile',
    u'File:FilePermissions',
    u'File:Directory',
    u'ExifTool:ExifToolVersion',
    u'File:FileModifyDate',
    u'File:FileName',
    u'File:FileSize',
    ]

while True:
    for (sampleno, sample) in \
        enumerate(db.fs.files.find({'exif': {'$exists': False}},
                  timeout=False)):
        try:
            logger.info('[%s] Processing sample %s' % (sampleno,
                        sample['sha256']))
            sample_key = {'_id': sample['_id']}
            job_key = {'md5': sample['md5']}

            # download sample file

            with exiftool.ExifTool() as et:
                logger.debug('[%s] Downloading data' % sampleno)
                filename = os.path.join('/', 'tmp', sample['sha256'])
                get_file(db, filename=filename, sha256=sample['sha256'])

                logger.debug('[%s] Analysing' % sampleno)
                metadata = et.get_metadata(filename)

                logger.debug('[%s] Deleting temporary file' % sampleno)
                os.remove(filename)

                logger.debug('[%s] Storing results into MongoDB'
                             % sampleno)

                for exifkey in uselessexifkey:
                    del metadata[exifkey]

                metadata = clean_data(metadata)

                db.fs.files.update(sample_key,
                                   {'$set': {'exif': metadata}},
                                   upsert=True)
                logger.info('[%s] Metadata updated' % sampleno)
        except Exception, e:
            logger.exception(e)
            pass

    logger.info('Sleeping %s minutes' % SLEEPTIME)
    time.sleep(SLEEPTIME * 60)  # Sleep 5 minutes between runs

