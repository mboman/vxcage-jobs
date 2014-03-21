#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
from pymongo import MongoClient
import gridfs
from utils import get_file, clean_data, Config
import time

import exiftool
import tempfile

JOBNAME = 'EXIF'
SLEEPTIME = 5

# create logger

logger = logging.getLogger(JOBNAME)
logger.setLevel(logging.DEBUG)

# create console handler with a higher log level

logch = logging.StreamHandler()
logch.setLevel(logging.ERROR)

# create formatter and add it to the handlers

formatter = \
    logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                      )
logch.setFormatter(formatter)

# add the handlers to the logger

logger.addHandler(logch)

client = MongoClient(host=Config().job.dbhost, port=Config().job.dbport)
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
        enumerate(db.fs.files.find({'exif': {'$exists': False}})):
        try:
            logger.info('[%s] Processing sample %s' % (sampleno,
                        sample['sha256']))
            key = {'sha256': sample['sha256']}

            # download sample file

            with exiftool.ExifTool() as et:
                logger.debug('[%s] Downloading data' % sampleno)
                tfile = tempfile.NamedTemporaryFile(mode='w+b')
                tfile.write(get_file(db, sha256=sample['sha256']))
                tfile.flush()
                logger.debug('[%s] Analysing' % sampleno)
                metadata = clean_data(et.get_metadata(tfile.name))
                logger.debug('[%s] Deleting temporary file' % sampleno)
                tfile.close()
                for exifkey in uselessexifkey:
                    del metadata[exifkey]

                logger.debug('[%s] Storing results into MongoDB'
                             % sampleno)

                # metadata = clean_data(metadata)

                db.fs.files.update(key, {'$set': {'exif': metadata}},
                                   upsert=True)
                logger.info('[%s] Metadata updated' % sampleno)
        except Exception, e:
            logger.exception(e)
            pass

    logger.info('Sleeping %s minutes' % SLEEPTIME)
    time.sleep(SLEEPTIME * 60)  # Sleep 5 minutes between runs

