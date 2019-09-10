import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.options
import os.path
import json
from tornado.options import define, options

from commander.lib.githubapi import GitHubAPI
from commander.lib.database import init_db


define("port", default=8000, help="run on the given port", type=int)


class BaseHandler(tornado.web.RequestHandler):

    def __init__(self, *args, **kwargs):
        super(BaseHandler, self).__init__(*args, **kwargs)
        self.sysconf = self.settings['sysconf']

    def get_current_user(self):
        return self.get_secure_cookie("username")


class LoginHandler(BaseHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        self.set_secure_cookie("username", self.get_argument("username"))
        self.redirect("/")


class WelcomeHandler(BaseHandler):
    # @tornado.web.authenticated
    def get(self):
        print(self.settings['sysconf'])
        self.render('main.html', user=self.current_user)


class LogoutHandler(BaseHandler):
    def get(self):
        if (self.get_argument("logout", None)):
            self.clear_cookie("username")
            self.redirect("/")


class SystemHandler(BaseHandler):
    def get(self):
        self.render('system.html', settings=self.sysconf)

    def post(self):
        sysconf = self.settings.sysconf
        for k in sysconf.keys():
            sysconf[k] = self.get_argument(k, sysconf[k])

        json.dump(sysconf, open('config/system.conf', 'w'))


class ConfigHandler(BaseHandler):
    # @tornado.web.authenticated
    def get(self, botid='default'):
        botconf = ''
        self.render('config.html', title='Configure', conf=botconf)

    # @tornado.web.authenticated
    def post(self):
        pass

    def update(self):
        pass


class CovertutilsHandler(BaseHandler):
    pass


class ResultHandler(BaseHandler):
    def get(self):
        # user, token, repo = self.sysconf['RetAccount'].split('$$')

        data = self.gh.get(self.sysconf['RetPath'] + 'test.dat')
        if not data:
            self.gh.put('data/test.dat', 'test1')
        self.gh.update('data/test.dat', 'test1', data['sha'])
        # ret = dict(count=len(data), result=data)
        self.write(data)


class TaskHandler(BaseHandler):
    pass


class WebsocketHandler(tornado.websocket.WebSocketHandler):
    def open(self):
        # self.application.shoppingCart.register(self.callback)
        pass

    def on_close(self):
        # self.application.shoppingCart.unregister(self.callback)
        pass

    def on_message(self):
        pass

    def callback(self, count):
        self.write_message('{"inventorycount":"%s"}' % count)


class ToyHomeApp(tornado.web.Application):

    def __init__(self, urls, **kwargs):
        super(ToyHomeApp, self).__init__(urls, **kwargs)
        # self.sysconf = self.settings['sysconf']
        dbpath = self.settings.get('db_path')
        dbpath = os.path.join(dbpath, 'data.db') if dbpath else 'data.db'
        self.db = init_db(dbpath)


if __name__ == "__main__":
    tornado.options.parse_command_line()

    settings = {
        "sysconf": json.load(open('config/system.conf', 'rb')),
        "db_path": os.path.join(os.path.dirname(__file__), "data"),
        "static_path": os.path.join(os.path.dirname(__file__), "static"),
        "template_path": os.path.join(os.path.dirname(__file__), "templates"),
        "cookie_secret": "bZJc2sWbQLKos6GkHn/VB9oXwQt8S0R0kRvJ5/xJ89E=",
        "xsrf_cookies": True,
        "autoreload": True,
        "debug": True,
        "login_url": "/login"
    }

    application = ToyHomeApp([
        (r'/', WelcomeHandler),
        (r'/login', LoginHandler),
        (r'/logout', LogoutHandler),
        (r'/system', SystemHandler),
        (r'/config', ConfigHandler),
        (r'/covertutils', CovertutilsHandler),
        (r'/result', ResultHandler),
        (r'/task', TaskHandler),
        (r'/websocket', WebsocketHandler)
    ], **settings)

    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()
