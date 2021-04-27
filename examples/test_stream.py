import logging
import os

logging.basicConfig(level=logging.INFO)
from elementapi import ElementAPI

apikey = os.getenv('ELEMENT_APIKEY', None)
api = ElementAPI(apikey, baseurl='stage.element-iot.com')

print("DEVICES STREAM\n"+16*'-')
for d in api.devices(stream=True):
    print(d)
