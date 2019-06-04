import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.options
import os.path
import json
from tornado.options import define, options

from commander.lib.githubapi import GitHubAPI
from commander.lib.sqlite import SQLite


define("port", default=8000, help="run on the given port", type=int)


class BaseHandler(tornado.web.RequestHandler):

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
        print(self.system_settings)
        self.render('system.html', settings=self.settings.sysconf)

    def post(self):
        for k in self.settings.keys():
            self.settings[k] = self.get_argument(k, self.settings[k])

        json.dump(self.sysconf, open('config/system.conf', 'w'))


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
        super().__init__(urls, **kwargs)
        self.system_settings = self.settings['sysconf']
        self.db = SQLite(
            self.system_settings.get('LocalDatabase', './data/data.db')
        )
        o, t, r = self.system_settings['BaseAccount'].split('$$')
        self.gh = GitHubAPI(gtoken=t, guser=o, grepo=r)


if __name__ == "__main__":
    tornado.options.parse_command_line()

    settings = {
        "sysconf": json.load(open('config/system.conf', 'rb')),
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
