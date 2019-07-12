import os

from .sqlite import SQLite
from .logger import logger as log


INITSQL = ["""\
CREATE TABLE 'Botlist' (
'ID' INTEGER PRIMARY KEY AUTOINCREMENT,
'BotID' VARCHAR(64),
'IP' VARCHAR(64),
'Platform' VARCHAR(128),
'Username' VARCHAR(64),
'Hostname' VARCHAR(64),
'SHA' VARCHAR(64),
'Group' VARCHAR(16) default 'BG0',
'Mark' VARCHAR(64),
'Status' VARCHAR(8),
'CheckTime' TIMESTAMP,
'CreateTime' TIMESTAMP not null default (datetime('now','localtime')),
'UpdateTime' TIMESTAMP
);
""", """\
CREATE TABLE 'Botcache' (
'ID' INTEGER PRIMARY KEY AUTOINCREMENT,
'BotID' INTEGER,
'Key' TEXT,
'Value' TEXT,
'CreateTime' TIMESTAMP not null default (datetime('now','localtime'))
);
""", """\
CREATE TABLE 'Taskresult' (
'TaskID' INTEGER PRIMARY KEY AUTOINCREMENT,
'BotID' INTEGER,
'Result' TEXT,
'StartTime' TIMESTAMP,
'ReportTime' TIMESTAMP,
'SHA' VARCHAR(64)
);
""", """\
CREATE TABLE 'Tasklist' (
'TaskID' INTEGER PRIMARY KEY AUTOINCREMENT,
'BotID' INTEGER,
'Name' VARCHAR(64),
'Status' VARCHAR(8),
'Module' VARCHAR(128),
'Type' VARCHAR(16),
'Settings' VARCHAR(128),
'StartTime' TIMESTAMP,
'FinishTime' TIMESTAMP,
'CreateTime' TIMESTAMP not null default (datetime('now','localtime'))
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
'ComPrivateKey' BLOB,
'BotPrivateKey' BLOB,
'AESKey' VARCHAR(128),
'HBTime' INTEGER,
'CreateTime' TIMESTAMP not null default (datetime('now','localtime')),
'UpdateTime' TIMESTAMP
);
""", """\
create trigger Botupdate before update on Botlist
for each row
begin
update Botlist set UpdateTime=datetime('now','localtime') where id=old.id;
update BotSettings set UpdateTime=datetime('now', 'localtime') where id=old.id;

end;
"""]
# """
# insert into `BotSettings` ('group_name', 'count') value ('default', 0);
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
