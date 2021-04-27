# TODO: accep uuid type in addition to string for ids !!!
import json
import logging
import re

import requests
import sys
import time

pyv, _, _, _, _ = sys.version_info
logger = logging.getLogger('elementapi')

IDENTIFIER_TYPES = ('id', 'slug', 'name', 'eui', 'address')


class ElementAPIException(Exception):
    msg = None

    def __init__(self, cause, msg=None, **kwargs):
        super(ElementAPIException, self).__init__(cause, **kwargs)
        self.msg = msg


class ElementAPI:
    apitoken = None
    baseurl = "element-iot.com"
    https = True
    port = 443
    apiversion = "/"
    sync = False

    def __init__(self, apitoken, baseurl=None, https=True, port=None, apiversion=1, sync=False):
        if baseurl:
            self.baseurl = baseurl

        self.https = https
        if port:
            self.port = port
        elif not port and https:
            self.port = 443
        elif not port and not https:
            self.port = 80  # most likely something bigger on onmprem deployments...

        self.apitoken = apitoken
        self.apiversion = "/api/v%s" % apiversion
        self.sync = sync

    # TODO: allow plain string paths !
    def genurl(self, _path=None, **opts):
        if 'limit' not in opts or not opts['limit'] or opts['limit'] > 100:
            opts['limit'] = 100

        if opts.get('nolimit', False):
            opts.pop('limit')

        rurl = "%s%s:%s%s/%s?auth=%s%s" \
               % (
                   "https://" if self.https else "http://",
                   self.baseurl,
                   self.port,
                   self.apiversion, '/'.join(_path) if _path else '/',
                   self.apitoken,
                   '' if (not opts or not len(opts))
                   else ('&%s' % '&'.join(['%s=%s' % (k, v) for k, v in opts.items() if v]))
               )
        return rurl

    def _log_request(self, meth, url, data=None):
        logger.info("HTTP %s : %s -> %s" % (
                meth,
                re.sub(r"auth=[a-zA-Z0-9]+", 'auth=xxxxxxxxxx', url),
                data
            )
        )

    def _req(self, uri=None, limit=None, lib_filter=None, stream=False, raise_rl=False, **opts):
        resp = None
        count = 0

        ilimit = limit

        if stream:
            url = self.genurl(
                (uri if uri else ()) + ('stream',),
                nolimit=True,
                **opts
            )
            self._log_request("GET (streaming)", url)
            resp = requests.get(url)

            if resp.status_code >= 400:
                raise ElementAPIException(resp.status_code, msg=resp.json())

            for line in resp.iter_lines():
                # filter out keep-alive new lines
                if line:
                    count += 1
                    decoded_line = line.decode('utf-8')
                    j = json.loads(decoded_line)
                    yield j['id'], j

        else:
            last_response = None

            while (resp is None or (
                    resp is not None and resp.get('retrieve_after_id', None)
            )) and (
                    not ilimit or ilimit and count < ilimit
            ):
                url = self.genurl(
                    (uri if uri else ()),
                    retrieve_after=(resp.get('retrieve_after_id', None) if resp else None),
                    limit=limit, **opts
                )
                self._log_request("GET", url)
                last_response = resp
                resp = requests.get(url)

                if resp.status_code >= 400:
                    if resp.status_code == 429 and not raise_rl:
                        # hit reate-limit

                        # sleep|block

                        rl_s = int(resp.headers.get('x-ratelimit-reset', 0))
                        logger.info('hit rate limit, blocking further requests for %s ms' % rl_s)

                        # keep last
                        resp = None if not last_response else {
                            'retrieve_after_id': last_response.get('retrieve_after_id', None)}

                        # using this async will lead to a LIFO behaviour !!!
                        time.sleep(rl_s / 1000.0)
                        continue
                    else:
                        # your bad ...
                        raise ElementAPIException(resp.status_code, msg=resp.json())

                resp = resp.json()
                if not resp:
                    raise ElementAPIException(resp.status_code, msg=resp.json())

                if resp and resp.get('body', None):
                    if isinstance(resp['body'], list):
                        for d in resp['body']:
                            count += 1
                            res = _filter(d, lib_filter)
                            if res and isinstance(res, dict):
                                yield d['id'], res
                            if ilimit and count == ilimit:
                                break
                    # a bit hacky ....
                    elif isinstance(resp['body'], dict):
                        r = []
                        for k, v in resp['body'].items():
                            r += v if isinstance(v, list) else []
                        for d in r:
                            count += 1
                            res = _filter(d, lib_filter)
                            if res and isinstance(res, dict):
                                yield d['id'], res
                            if ilimit and count == ilimit:
                                break

    def tags(self, limit=None, **opts):

        # no streaming yet
        opts.pop('stream', None)

        for d in self._req(uri=('tags',), limit=limit, **opts):
            yield d

    # single call
    def tag(self, tag, limit=None, **opts):
        if not tag:
            raise ElementAPIException('required tag id or slug')

        # no streaming yet
        opts.pop('stream', None)

        url = self.genurl(('tags', tag,), **opts)
        self._log_request("GET", url)
        resp = requests.get(url).json()

        return resp.get('body', None)

    def devices(self, limit=None, tag=None, **opts):

        # no streaming yet
        opts.pop('stream', None)

        if tag:
            uri = ('tags', tag, 'devices')
        else:
            uri = ('devices',)

        # bypass that f*ckin' pagination bug by giving sort_direction
        for d in self._req(uri=uri, limit=limit, sort_direction='ascending', **opts):
            yield d

    def packets(self, device, limit=None, **opts):
        if not device:
            raise ElementAPIException('required device name or slug')
        for p in self._req(uri=('devices', device, 'packets'), limit=limit, **opts):
            yield p

    def readings(self, device, limit=None, **opts):
        if not device:
            raise ElementAPIException('required device name or slug')
        for r in self._req(uri=('devices', device, 'readings'), limit=limit, **opts):
            yield r

    # single call
    def device(self, device, **opts):
        if not device:
            raise ElementAPIException('required device name or slug')

        # no streaming yet
        opts.pop('stream', None)

        url = self.genurl(('devices', device,), **opts)
        self._log_request("GET", url)
        meth = opts.get('method', 'get').lower()

        resp = requests.get(url).json()
        if meth == 'delete':
            resp = requests.delete(url).json()

        return resp.get('body', None)

    def interfaces(self, device, limit=None, **opts):
        if not device:
            raise ElementAPIException('required device name or slug')

        # no streaming yet
        opts.pop('stream', None)

        url = self.genurl(('devices', device, 'interfaces'), **opts)
        self._log_request("GET", url)
        resp = requests.get(url).json()

        for i in resp.get('body', []):
            yield i['id'], i

    def apikeys(self, limit=None, **opts):

        # no streaming yet
        opts.pop('stream', None)

        for k in self._req(uri=('api_keys'), limit=limit, **opts):
            yield k

    def create(self, path, data):
        # TODO: if path is iterable -> tuple
        url = self.genurl((path,), nolimit=True)
        self._log_request("POST", url)
        # TODO: data type check !?!
        resp = requests.post(url, json=data)

        js = resp.json()
        if resp.status_code >= 400:
            raise ElementAPIException(resp.status_code, msg=resp.json())
        return resp.status_code, js.get('body', [])

    def update(self, path, data):
        # TODO: if path is iterable -> tuple
        url = self.genurl((path,), nolimit=True)
        self._log_request("PUT", url)
        # TODO: data type check !?!
        resp = requests.put(url, json=data)
        # print("!!!!", resp.text)

        js = resp.json()
        if resp.status_code >= 400:
            raise ElementAPIException(resp.status_code, msg=resp.text)
        return resp.status_code, js.get('body', [])

    def drivers(self, limit=None, **opts):

        # no streaming yet
        opts.pop('stream', None)

        for d in self._req(uri=('drivers',), limit=limit, **opts):
            yield d

    def mandates(self, limit=None, **opts):

        # no streaming yet
        opts.pop('stream', None)

        for d in self._req(uri=('mandates',), limit=limit, **opts):
            yield d

    def driver_instances(self, limit=None, **opts):

        # no streaming yet
        opts.pop('stream', None)

        for d in self._req(uri=('drivers', 'instances'), limit=limit, **opts):
            yield d

    def get_devices_by(self, by, identifier, limit=None, **opts):

        # no streaming yet
        opts.pop('stream', None)

        if by not in IDENTIFIER_TYPES:
            raise ElementAPIException('unknown identifier type: %s' % identifier)
        for d in self._req(uri=('devices', 'by-%s' % by, identifier), limit=limit, **opts):
            yield d

    def get_packets_by(self, by, identifier, limit=None, **opts):
        if by not in IDENTIFIER_TYPES:
            raise ElementAPIException('unknown identifier type: %s' % identifier)
        for d in self._req(uri=('devices', 'by-%s' % by, identifier, 'packets'), limit=limit, **opts):
            yield d

    def get_readings_by(self, by, identifier, limit=None, **opts):
        if by not in IDENTIFIER_TYPES:
            raise ElementAPIException('unknown identifier type: %s' % identifier)
        for d in self._req(uri=('devices', 'by-%s' % by, identifier, 'readings'), limit=limit, **opts):
            yield d


# these are local only filters !
# only works at level 0 atm !
def _filter(inpt, filter):
    if not filter or not inpt or not type(filter) == dict or not len(filter):
        return inpt
    else:
        if pyv == 3:
            return inpt if filter.items() <= inpt.items() else None
        else:
            return inpt if filter.viewitems() <= inpt.viewitems() else None
