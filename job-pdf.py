#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
import logging
import tempfile
import time

from pymongo import MongoClient
import gridfs

from pdfid import PDFiD2JSON, PDFiD
from utils import get_file, clean_data, Config

JOBNAME = 'PDF'
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


def get_pdfid(file_data):
    metadata = None
    options = {}
    options['all'] = True
    options['extra'] = False
    options['disarm'] = False
    options['force'] = False

    tfile = tempfile.NamedTemporaryFile(mode='w+b')
    tfile.write(file_data)
    tfile.flush()
    metadata = json.loads(PDFiD2JSON(PDFiD(tfile.name, options['all'],
                          options['extra'], options['disarm'],
                          options['force']), options['force']))
    tfile.close()

    return metadata


while True:
    for (sampleno, sample) in \
        enumerate(db.fs.files.find({'$and': [{'pdfid': {'$exists': False}},
                  {'filetype': {'$regex': 'PDF.*'}}]})):
        try:
            logger.info('[%s] Processing sample %s' % (sampleno,
                        sample['sha256']))
            key = {'sha256': sample['sha256']}

            # download sample file

            logger.debug('[%s] Downloading data' % sampleno)
            data = get_file(db, sha256=sample['sha256'])

            # Do analysis

            logger.debug('[%s] Analysing PDF' % sampleno)
            pdfid = clean_data(get_pdfid(data))

            # Store results

            if pdfid:
                logger.debug('[%s] Storing results into MongoDB'
                             % sampleno)
                db.fs.files.update(key, {'$set': {'pdfid': pdfid}},
                                   upsert=True)
            logger.info('[%s] Metadata updated' % sampleno)
        except Exception, e:
            logger.exception(e)
            pass

    logger.info('Sleeping %s minutes' % SLEEPTIME)
    time.sleep(SLEEPTIME * 60)

