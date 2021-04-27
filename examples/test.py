import json
import logging
import os
import sys

logging.basicConfig(level=logging.INFO)
from elementapi import ElementAPI


apikey = os.getenv('ELEMENT_APIKEY', None)
if not apikey:
    sys.exit(-1)

api = ElementAPI(apikey, baseurl='stage.element-iot.com')

print("TAGS\n"+16*'-')
for t in api.tags(lmit=1):
    print(json.dumps(t,sort_keys=True, indent=2))

print()

print("DEVICES STREAM\n"+16*'-')
for d in api.devices(stream=True, filter={'slug': None, 'updated_at': None}):
    print('* ', d[0])
    id = d[0]

print()

print("DEVICES\n"+16*'-')
for d in api.devices(limit=10, filter={'slug': None, 'updated_at': None}):
    print("*", d[0])

print()

print("INTERFACES\n"+16*'-')
for i in api.interfaces(d[0]):
    print(i)

print()

print("PACKETS\n"+16*'-')
for p in api.packets(d[0], limit=10):
    print(p)

print()

print("READINGS\n"+16*'-')
for r in api.readings(d[0], limit=10):
    print(r)


print("SINGLE DEV [404]\n"+16*'-')
for d in api.device('11111'):
    print("*", d[0])
