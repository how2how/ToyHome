'''
Copyright 2017 John Torakis

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

import imp
import sys
import logging

from contextlib import contextmanager
try:
    from urllib2 import urlopen, Request
except ImportError:
    from urllib.request import urlopen, Request

# log_FORMAT = '%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s'
log_FORMAT = '[%(asctime)s] [%(levelname)s] [ %(filename)s:%(lineno)s] %(message)s '
logging.basicConfig(format=log_FORMAT)
logger = logging.getLogger(__name__)
# logger.setLevel(logging.WARN)
logger.setLevel(logging.INFO)

NON_SOURCE = False


class HttpImporter(object):

    def __init__(self, modules, base_url):
        self.module_names = modules
        self.base_url = base_url + '/'
        self.non_source = NON_SOURCE

    def find_module(self, fullname, path=None):
        logger.debug("FINDER=================")
        logger.debug("[!] Searching %s" % fullname)
        logger.debug("[!] Path is %s" % path)
        logger.debug("[@]Checking if in domain >")
        if fullname.split('.')[0] not in self.module_names:
            return None

        logger.debug("[@]Checking if built-in >")
        try:
            loader = imp.find_module(fullname, path)
            if loader:
                return None
        except ImportError:
            pass
        logger.debug("[@]Checking if it is name repetition >")
        if fullname.split('.').count(fullname.split('.')[-1]) > 1:
            return None

        logger.debug("[*]Module/Package '%s' can be loaded!" % fullname)
        return self

    def load_module(self, name):
        imp.acquire_lock()
        logger.debug("LOADER=================")
        logger.debug("[+] Loading %s" % name)
        if name in sys.modules:
            logger.info('[+] Module "%s" already loaded!' % name)
            imp.release_lock()
            return sys.modules[name]

        if name.split('.')[-1] in sys.modules:
            imp.release_lock()
            logger.info('[+] Module "%s" loaded as a top level module!' % name)
            return sys.modules[name.split('.')[-1]]

        module_url = self.base_url + '%s.py' % name.replace('.', '/')
        package_url = self.base_url + '%s/__init__.py' % name.replace('.', '/')
        final_url = None
        final_src = None

        try:
            logger.debug("[+] Trying to import as package from: '%s'" % package_url)
            package_src = None
            if self.non_source:
                package_src = self.__fetch_compiled(package_url)
            if package_src is None:
                package_src = urlopen(package_url).read()
                # package_src = get_raw(package_url)
            final_src = package_src
            final_url = package_url
        except IOError as e:
            package_src = None
            logger.debug("[-] '%s' is not a package:" % name)

        if final_src is None:
            try:
                logger.debug("[+] Trying to import as module from: '%s'" % module_url)
                module_src = None
                if self.non_source:
                    module_src = self.__fetch_compiled(module_url)
                if module_src is None:
                    module_src = urlopen(module_url).read()
                    # module_src = get_raw(module_url)
                final_src = module_src
                final_url = module_url
            except IOError as e:
                module_src = None
                logger.debug("[-] '%s' is not a module:" % name)
                logger.warning("[!] '%s' not found in HTTP repository. Moving to next Finder." % name)
                imp.release_lock()
                return None
        logger.info(final_src)
        logger.info("[+] Importing '%s'" % name)
        mod = imp.new_module(name)
        mod.__loader__ = self
        mod.__file__ = final_url
        if not package_src:
            mod.__package__ = name
        else:
            mod.__package__ = name.split('.')[0]

        mod.__path__ = ['/'.join(mod.__file__.split('/')[:-1]) + '/']
        logger.debug("[+] Ready to execute '%s' code" % name)
        sys.modules[name] = mod
        exec(final_src, mod.__dict__)
        logger.info("[+] '%s' imported succesfully!" % name)
        imp.release_lock()
        return mod

    def __fetch_compiled(self, url):
        import marshal
        module_src = None
        try:
            # module_compiled = urlopen(url + 'c').read()
            module_compiled = get_raw(url + 'c')
            try:
                module_src = marshal.loads(module_compiled[8:])
                return module_src
            except ValueError:
                pass
            try:
                module_src = marshal.loads(module_compiled[12:])
                return module_src
            except ValueError:
                pass
        except IOError as e:
            logger.debug("[-] No compiled version ('.pyc') for '%s' module found!" % url.split('/')[-1])
        return module_src


def get_raw(url, headers=None):
    req = Request(url)
    req.headers = {'User-Agent': 'Test-App',
                   'Accept': 'application/vnd.github.v3+json'}
    if headers:
        req.headers.update(headers)
    return urlopen(req).read()


@contextmanager
def remote_repo(modules, base_url='http://localhost:8000/'):
    importer = add_remote_repo(modules, base_url)
    yield
    remove_remote_repo(base_url)


def add_remote_repo(modules, base_url='http://localhost:8000/'):
    if not base_url.startswith('https'):
        logger.warning("[!] Using non HTTPS URLs ('%s') can be a security hazard!" % base_url)
    importer = HttpImporter(modules, base_url)
    sys.meta_path.append(importer)
    return importer


def remove_remote_repo(base_url):
    for importer in sys.meta_path:
        try:
            if importer.base_url[:-1] == base_url:  # an extra '/' is always added
                sys.meta_path.remove(importer)
                return True
        except Exception as e:
            return False


def __create_github_url(username, repo, branch='master'):
    github_raw_url = 'https://raw.githubusercontent.com/{user}/{repo}/{branch}/'
    return github_raw_url.format(user=username, repo=repo, branch=branch)


def __create_bitbucket_url(username, repo, branch='master'):
    bitbucket_raw_url = 'https://bitbucket.org/{user}/{repo}/raw/{branch}/'
    return bitbucket_raw_url.format(user=username, repo=repo, branch=branch)


def _add_git_repo(url_builder, username=None, repo=None, module=None, branch=None, commit=None):
    if username is None or repo is None:
        raise Error("'username' and 'repo' parameters cannot be None")
    if commit and branch:
        raise Error("'branch' and 'commit' parameters cannot be both set!")

    if commit:
        branch = commit
    if not branch:
        branch = 'master'
    if not module:
        module = repo
    if type(module) == str:
        module = [module]
    url = url_builder(username, repo, branch)
    return add_remote_repo(module, url)


@contextmanager
def github_repo(username=None, repo=None, module=None, branch=None, commit=None):
    importer = _add_git_repo(__create_github_url,
        username, repo, module=module, branch=branch, commit=commit)
    yield
    url = __create_github_url(username, repo, branch)
    remove_remote_repo(url)


@contextmanager
def bitbucket_repo(username=None, repo=None, module=None, branch=None, commit=None):
    importer = _add_git_repo(__create_bitbucket_url,
        username, repo, module=module, branch=branch, commit=commit)
    yield
    url = __create_bitbucket_url(username, repo, branch)
    remove_remote_repo(url)


__all__ = [
    'HttpImporter',

    'add_remote_repo',
    'remove_remote_repo',

    'remote_repo',
    'github_repo',
    'bitbucket_repo',
]
