#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
from pymongo import MongoClient
import gridfs

import urllib
import urllib2

import requests

import json

from utils import get_file, clean_data, Config

JOBNAME = 'VIRUSTOTAL'
SLEEPTIME = 1

# create logger

logger = logging.getLogger(JOBNAME)
logger.setLevel(logging.DEBUG)

# create console handler with a higher log level

logch = logging.StreamHandler()
logch.setLevel(logging.ERROR)

# create formatter and add it to the handlers

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logch.setFormatter(formatter)

# add the handlers to the logger

logger.addHandler(logch)

client = MongoClient(host=Config().job.dbhost, port=Config().job.dbport)
db = client.vxcage
fs = gridfs.GridFS(db)

url = 'https://www.virustotal.com/vtapi/v2/file/report'
api_key = Config().virustotal.api_key
if Config().virustotal.proxy:
    proxy = {'http': Config().virustotal.proxy,
             'https': Config().virustotal.proxy}

while True:
    for (sampleno, sample) in enumerate(db.fs.files.find({'virustotal': {'$exists': False}})):
        try:
            logger.info('[%s] Processing sample %s' % (sampleno, sample['sha256']))
            key = {'sha256': sample['sha256']}
            parameters = {'resource': sample['sha256'], 'apikey': api_key}

            logger.debug('[%s] Analysing' % sampleno)
            r = requests.post(url, data=parameters, proxies=proxy)

            VTjson = None
            logger.debug('[%s] Response headers: %s' % (sampleno, r.headers))
            logger.debug('[%s] Response content: %s' % (sampleno, r.content))
            try:
                VTjson = clean_data(r.json())
            except Exception:
                try:
                    VTjson = clean_data(json.loads(r.text))
                except Exception:
                    logger.debug('[%s] Unknown response: %s' % (sampleno, r.content))

            if VTjson:
                if VTjson['response_code'] == 1:
                    logger.debug('[%s] Storing results into MongoDB' % sampleno)
                    db.fs.files.update(key, {'$set': {'virustotal': VTjson}}, upsert=True)
                    logger.info('[%s] Metadata updated' % sampleno)
                else:
                    logger.warn('[%s] File Does Not Exist in VirusTotal' % sampleno)
        except Exception, e:

            logger.exception(e)
            pass

    logger.info('Sleeping %s minutes' % SLEEPTIME)
    time.sleep(SLEEPTIME * 60)

