#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import time

from pymongo import MongoClient
import gridfs

try:
    import magic
except ImportError:
    pass

from utils import get_file, clean_data, Config


def get_type(file_data):
    try:
        ms = magic.open(magic.MAGIC_NONE)
        ms.load()
        file_type = ms.buffer(file_data)
        logger.debug('Got magic through method #1 [ms.buffer(file_data)]'
                     )
    except:
        try:
            file_type = magic.from_buffer(file_data)
            logger.debug('Got magic through method #2 [magic.from_buffer(file_data)]'
                         )
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
                logger.debug('Got magic through method #3 [OS command execution]'
                             )
            except:
                return None

    return file_type


JOBNAME = 'FILEMAGIC'
SLEEPTIME = 1

# create logger

logger = logging.getLogger(JOBNAME)
logger.setLevel(logging.DEBUG)

# create console handler with a higher log level

logch = logging.StreamHandler()
logch.setLevel(logging.INFO)

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
        for (sampleno, sample) in enumerate(db.fs.files.find({'filetype': {'$exists': False}})):
            try:
                logger.info('[%s] Processing sample %s' % (sampleno, sample['sha256']))
                samplekey = {'sha256': sample['sha256']}

                # download sample file

                logger.debug('[%s] Downloading data' % sampleno)
                data = get_file(db, sha256=sample['sha256'])

                # Do analysis

                logger.debug('[%s] Analysing' % sampleno)
                file_type = clean_data(get_type(data))

                # Store results

                logger.debug('[%s] Storing results into MongoDB' % sampleno)
                if file_type:
                    db.fs.files.update(samplekey, {'$set': {'filetype': file_type}}, upsert=True)

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

