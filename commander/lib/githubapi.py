import json

try:
    from urllib2 import urlopen, Request
except ImportError:
    from urllib.request import urlopen, Request
import logging
# fmt = '%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s'
fmt = '[%(asctime)s] [%(levelname)s] [ %(filename)s:%(lineno)s ] %(message)s '
logging.basicConfig(level=logging.INFO, format=fmt)


class GitHubAPI(object):

    def __init__(self, gtoken=None, guser=None, gpwd=None,
                 grepo=None, gbranch='master'):
        if not gtoken and not gpwd:
            raise('Token or password must have one')
        self.token = gtoken
        self.owner = guser
        self.gpwd = gpwd
        self.repo = grepo
        self.branch = gbranch

    @staticmethod
    def _request(method='GET', uri=None, data=None, headers=None, timeout=30):
        url = 'https://api.github.com'
        url = uri if url in uri else (url + uri)
        req = Request(url)
        req.timeout = timeout
        req.headers = {'User-Agent': 'App',
                       'Accept': 'application/vnd.github.v3+json'}
        if headers:
            req.headers.update(headers)
        req.get_method = lambda: method
        if data:
            data = json.dumps(data, ensure_ascii=False)
        try:
            logging.info('Start to request: %s' % url)
            logging.debug('Request data: %s' % data)
            rsp = urlopen(req, data)
        except Exception as e:
            logging.error('[-] Request error: %s' % url)
            logging.exception(e)
            rsp = None
        return rsp

    def request(self, method='GET', uri=None, data=None, headers=None):
        headers = headers or {}
        if self.token:
            headers.update({'Authorization': 'token ' + self.token})
        else:
            up = ':'.join((self.owner, self.gpwd))
            auth_hash = up.encode('base64').strip()
            headers.update({'Authorization': 'Basic ' + auth_hash})

        return GitHubAPI._request(method=method, uri=uri,
                                  data=data, headers=headers)

    def GHput(self, path, content, msg='new file'):
        """
        PUT /repos/:owner/:repo/contents/:path
        """
        uri = '/repos/%s/%s/contents/%s' % (self.owner, self.repo, path)
        data = {'message': msg, 'content': content.encode('base64')}
        logging.info('[*] Save result to %s' % path)
        return self.request('PUT', uri, data)

    def GHget(self, path):
        """
        GET /repos/:owner/:repo/contents/:path
        """
        uri = '/repos/%s/%s/contents/%s' % (self.owner, self.repo, path)
        rsp = self.request(uri=uri)
        content = json.loads(rsp.read().strip()) if rsp else {}
        # return content.get('content', '').decode('base64'), content
        return content

    def GHupdate(self, path, content, sha, msg='update file'):
        """
        PUT /repos/:owner/:repo/contents/:path
        """
        uri = '/repos/%s/%s/contents/%s' % (self.owner, self.repo, path)
        data = {'message': msg,
                'content': content.encode('base64'),
                'sha': sha}
        return self.request('PUT', uri, data)

    def GHdelete(self, path, sha, msg='delete file'):
        """
        DELETE /repos/:owner/:repo/contents/:path
        """
        uri = '/repos/%s/%s/contents/%s' % (self.owner, self.repo, path)
        data = {'message': msg, 'sha': sha}
        return self.request('DELETE', uri, data)
