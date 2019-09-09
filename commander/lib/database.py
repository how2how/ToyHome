import os

from .sqlite import SQLite
from .logger import logger as log


# Group default: hashlib.md5('default').hexdigest()[8:24]

INITSQL = ["""\
CREATE TABLE 'BotList' (
'ID' INTEGER PRIMARY KEY AUTOINCREMENT,
'BotID' VARCHAR(64),
'IP' VARCHAR(64),
'Platform' VARCHAR(128),
'Username' VARCHAR(64),
'Hostname' VARCHAR(64),
'SHA' VARCHAR(64),
'Group' VARCHAR(16) default '5f03d33d43e04f8f',
'Mark' VARCHAR(64),
'Status' VARCHAR(8),
'CheckTime' TIMESTAMP,
'CreateTime' TIMESTAMP not null default (datetime('now','localtime')),
'UpdateTime' TIMESTAMP
);
""", """\
CREATE TABLE 'BotCache' (
'ID' INTEGER PRIMARY KEY AUTOINCREMENT,
'BotID' INTEGER,
'Key' TEXT,
'Value' TEXT,
'CreateTime' TIMESTAMP not null default (datetime('now','localtime'))
);
""", """\
CREATE TABLE 'TaskResult' (
'TaskID' INTEGER PRIMARY KEY AUTOINCREMENT,
'BotID' INTEGER,
'Result' TEXT,
'BuildTime' TIMESTAMP,
'StartTime' TIMESTAMP,
'SHA' VARCHAR(64)
);
""", """\
CREATE TABLE 'TaskList' (
'TaskID' INTEGER PRIMARY KEY AUTOINCREMENT,
'BotID' INTEGER,
'Name' VARCHAR(64),
'Status' VARCHAR(8),
'Module' VARCHAR(128),
'Type' VARCHAR(16),
'args' VARCHAR(128),
'kwargs' VARCHAR(128),
'Start' INTEGER,
'Step' INTEGER,
'End' INTEGER,
'CreateTime' TIMESTAMP not null default (datetime('now','localtime'))
'UpdateTime' TIMESTAMP
);
""", """\
CREATE TABLE 'BotSettings' (
'ID' INTEGER PRIMARY KEY AUTOINCREMENT,
'BotID' INTEGER,
'BaseGH' VARCHAR(512),
'ConfPath' VARCHAR(128),
'ModulesPath' VARCHAR(128),
'RetGH' VARCHAR(512),
'RetPath' VARCHAR(128),
'KnockPath' VARCHAR(128),
'ComPrivateKey' VARCHAR(128),
'BotPrivateKey' VARCHAR(128),
'AESKey' VARCHAR(128),
'HBTime' INTEGER,
'CreateTime' TIMESTAMP not null default (datetime('now','localtime')),
'UpdateTime' TIMESTAMP
);
""", """\
create trigger BotUpdate before update on BotList
for each row
begin
update BotList set UpdateTime=datetime('now','localtime') where id=old.id;
end;
""", """\
create trigger BotSettingsUpdate before update on BotSettings
for each row
begin
update BotSettings set UpdateTime=datetime('now', 'localtime') where id=old.id;
end;
""", """\
create trigger TaskListUpdate before update on TaskList
for each row
begin
update TaskList set UpdateTime=datetime('now', 'localtime') where id=old.id;
end;
"""]
# """
# insert into `BotSettings` (BotID, 'BaseGH', 'ConfPath', 'RetGH', 'RetPath', 'CommPrivateKey', 'BotPrivateKey', 'AESKey', 'HBTime') value (
# 0,"how2how$$3bb7f838bdc6a4533e9cad5a9ee83859fea5c78b$$toy", "conf", "how2how$$3bb7f838bdc6a4533e9cad5a9ee83859fea5c78b$$toy", "data",
# "./data/srvPrivate_default.pem", "./data/botPrivate_default.pem", "Default_AES_KEY_Change_YOURSELF", 60);
# """


def init_db(self, dbf):
    if not os.path.exists(dbf):
        log.info('Init database...')
        database = SQLite(dbf)
        for sql in INITSQL:
            database.execute(sql)
    else:
        database = SQLite(dbf)

    return database
