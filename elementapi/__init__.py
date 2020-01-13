# TODO: accep uuid type in addition to string for ids !!!

import sys
import re

import requests
import logging


pyv, _, _, _, _ = sys.version_info
logger = logging.getLogger('elementapi')


class ElementAPIException(Exception):
    def __init__(self, cause, **kwargs):
        super(ElementAPIException, self).__init__(cause, **kwargs)


class ElementAPI:
    apitoken = None
    baseurl="element-iot.com"
    https = True
    port = 443
    apiversion="/"
    sync = False

    def __init__(self, apitoken, baseurl=None, https=True, port=None, apiversion=1, sync=False):
        if(baseurl):
            self.baseurl=baseurl

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

    def genurl(self, _path=None, **opts):
        if 'limit' not in opts or not opts['limit'] or opts['limit']>100:
            opts['limit'] = 100

        if opts.get('nolimit', False):
            opts.pop('limit')

        rurl = "%s%s:%s%s/%s?auth=%s%s"\
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
        logger.info("HTTP %s : %s -> %s" %
                    (
                        meth,
                        re.sub(
                            r"auth=([a-z0-9]*$)|([a-z0-9]+&)",
                            ("auth=xxxxxxxxxxxx"+("&" if self.apitoken+"&" in url else "")).replace('auth=auth=', 'auth='),
                            url
                        ),
                        data
                    )
        )

    def _req(self, uri=None, limit=None, filter=None, **opts):
        resp = None
        count = 0

        ilimit = limit

        while (resp is None or (resp is not None and resp.get('retrieve_after_id', None)))\
               and (not ilimit or ilimit and count < ilimit
        ):
            url = self.genurl(
                (uri if uri else ()),
                retrieve_after=(resp.get('retrieve_after_id', None) if resp else None),
                limit=limit, **opts
            )
            self._log_request("GET", url)
            resp = requests.get(url)

            if resp.status_code >= 400:
                raise ElementAPIException(resp.status_code)

            resp = resp.json()
            if not resp:
                raise ElementAPIException(resp.text)

            if resp and resp.get('body', None):
                if isinstance(resp['body'], list):
                    for d in resp['body']:
                        count += 1
                        res = _filter(d, filter)
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
                        res = _filter(d, filter)
                        if res and isinstance(res, dict):
                            yield d['id'], res
                        if ilimit and count == ilimit:
                            break

    def tags(self, limit=None, **opts):
        for d in self._req(uri=('tags', ), limit=limit, **opts):
            yield d

    # single call
    def tag(self, tag, limit=None, **opts):
        if not tag:
            raise ElementAPIException('required tag id or slug')
        url = self.genurl(('tags', tag,), **opts)
        self._log_request("GET", url)
        resp = requests.get(url).json()

        return resp.get('body', None)

    def devices(self, limit=None, tag=None, **opts):
        if(tag):
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
        url = self.genurl(('devices', device,), **opts)
        self._log_request("GET", url)
        meth = opts.get('method', 'get').lower()

        if meth == 'get':
            resp = requests.get(url).json()
        if meth == 'delete':
            reso = requests.delete(url).json()

        return resp.get('body', None)

    def interfaces(self, device, limit=None, **opts):
        if not device:
            raise ElementAPIException('required device name or slug')
        url = self.genurl(('devices', device, 'interfaces'), **opts)
        self._log_request("GET", url)
        resp = requests.get(url).json()

        for i in resp.get('body', []):
            yield i['id'], i

    def apikeys(self, limit=None, **opts):
        for k in self._req(uri=('api_keys'), limit=limit, **opts):
            yield k

    def create(self, path, data):
        # TODO: if path is iterable -> tuple
        url = self.genurl((path,), nolimit=True)
        self._log_request("POST", url)
        # TODO: data type check !?!
        resp = requests.post(url, json=data)

        try:
            return resp.status_code, resp.json().get('body', [])
        except Exception as e:
            raise ElementAPIException('failed to create %s %s -> [%s] : %s' % (path, resp.status_code, type(e), str(e)))

    def update(self, path, data):
        # TODO: if path is iterable -> tuple
        url = self.genurl((path,), nolimit=True)
        self._log_request("PUT", url)
        # TODO: data type check !?!
        resp = requests.put(url, json=data)

        try:
            return resp.status_code, resp.json().get('body', [])
        except Exception as e:
            raise ElementAPIException('failed to update %s %s -> [%s] : %s' % (path, resp.status_code, type(e), str(e)))

    def drivers(self, limit=None, **opts):
        for d in self._req(uri=('drivers', ), limit=limit, **opts):
            yield d

    def driver_instances(self, limit=None, **opts):
        for d in self._req(uri=('drivers', 'instances'), limit=limit, **opts):
            yield d


# only works at level 0 atm !
def _filter(inpt, filter):
    if not filter or not inpt or not type(filter) == dict or not len(filter):
        return inpt
    else:
        if pyv == 3:
            return inpt if filter.items() <= inpt.items() else None
        else:
            return inpt if filter.viewitems() <= inpt.viewitems() else None
