import logging
import os

logging.basicConfig(level=logging.INFO)
from elementapi import ElementAPI

apikey = os.getenv('ELEMENT_APIKEY', None)

# ensure to have a limited key ... 5/10000 for example
api = ElementAPI(apikey, baseurl='stage.element-iot.com')

print("DEVICES\n"+16*'-')
for d in api.devices():
    print(d)

