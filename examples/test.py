import logging
logging.basicConfig(level=logging.INFO)
from elementapi import ElementAPI

api = ElementAPI("<your api key>", baseurl='stage.element-iot.com')

print("TAGS\n"+16*'-')
for t in api.tags():
    print(t)

print("DEVICES STREAM\n"+16*'-')
for d in api.devices(stream=True, filter={'slug': None, 'updated_at': None}):
    print(d)

print("DEVICES\n"+16*'-')
for d in api.devices(limit=10, filter={'slug': None, 'updated_at': None}):
    print(d)


print("INTERFACES\n"+16*'-')
for i in api.interfaces('<your device uuid>'):
    print(i)

print("PACKETS\n"+16*'-')
for p in api.packets('<your device uuid>', limit=10):
    print(p)

print("READINGS\n"+16*'-')
for r in api.readings('<your device uuid>', limit=10):
    print(r)

