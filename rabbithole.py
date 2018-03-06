#!/usr/bin/python3
# -*- coding: utf-8 -*-

import requests
import os
import errno
import configparser
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from daemon import Daemon
import time
import sys
import logging



home_dir = os.path.expanduser("~")
config = configparser.ConfigParser()
uid = os.getuid()
pidfile = '/var/run/user/{:d}/rabbithole.pid'.format(uid)
local_share_path = os.path.join(home_dir, '.local/share/rabbithole')
logfile = os.path.join(local_share_path, 'rabbithole.log')
os.makedirs(local_share_path, exist_ok=True)
# list of active observers
observers = []
logging.basicConfig(
    filename=logfile, 
    level=logging.DEBUG, 
    format="%(asctime)s [%(levelname)8s] %(message)s", 
    datefmt='%d-%m-%Y %H:%M:%S'
)



class YandexApi(object):
    host = 'https://cloud-api.yandex.net'
    version = 'v1'
    client_id = '14e6df77206c47ab8d4e0414503ed242'
    prefix = '{}/{}'.format(host, version)

    def __init__(self, token):
        self.token = token
        self.headers = {
            'Authorization': 'OAuth {}'.format(token),
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }

    def about_disk(self):
        logging.debug('Get cloud info')
        url = '{}/disk/'.format(self.prefix)
        r = requests.get(url, headers=self.headers)
        data = r.json()

        if r.status_code != 200:
            logging.error('Failed to get cloud info: status_code=%d (%s)', r.status_code, r.reason)
            return None
        
        data['free_space'] = data['total_space'] - data['used_space']
        return data

    def _get_url_for_post_file(self, path):
        logging.debug('Get url for upload to %s', path)
        url = '{}/disk/resources/upload'.format(self.prefix)
        payload = {
            'path': path,
            'overwrite': 'false',
        }
        r = requests.get(url, headers=self.headers, params=payload)
        data = r.json()

        if r.status_code == 200:
            return data['href']
        else:
            logging.error(data['description'])
            return None

    @staticmethod
    def total_logging(secs, filesize_bytes):
        mbs = filesize_bytes / 1024 / 1024 / secs
        if mbs > 1:
            logging.debug('Done: %f sec, %f MB/s', secs, mbs)
        else:
            kbs = filesize_bytes / 1024 / secs
            logging.debug('Done: %f sec, %f KB/s', secs, kbs)

    def post_file(self, path, local_path):
        logging.debug('Transfer file %s to cloud', local_path)
        if self.enough_space(local_path) and self.allowed_size(local_path):
            put_url = self._get_url_for_post_file(path)
            if put_url:
                files = {'file': open(local_path, 'rb')}
                r = requests.put(put_url, files=files)

                if r.status_code == 201:
                    filesize_bytes = os.path.getsize(local_path)
                    if r.elapsed:
                        ts = r.elapsed.total_seconds()
                        self.total_logging(ts, filesize_bytes)
                    os.remove(local_path)
                else:
                    logging.error('Upload failed: status_code=%d (%s)', r.status_code, r.reason)

                return r.status_code
        else:
            logging.error('The file size is more valid or there is insufficient free space in the cloud.')
            return -1

    def create_dir(self, path):
        if path[0] == '/':
            path = path[1:]
        logging.debug('Create dir: %s', path)
        dir_url = '{}/disk/resources'.format(self.prefix)
        payload = {
            'path': path,
        }
        r = requests.put(dir_url, params=payload, headers=self.headers)

        if r.status_code == 201:
            logging.debug('Dir %s created', path)
            return True
        else:
            logging.error('Create dir failed: status_code=%d (%s), message=%s', r.status_code, r.reason, r.json())
            return False

    def enough_space(self, local_path):
        """ Checks that there is enough free space in the cloud """
        info = self.about_disk()
        free_space = info['free_space']
        statinfo = os.stat(local_path)
        filesize_bytes = statinfo.st_size
        if free_space > filesize_bytes:
            return True
        else:
            return False

    def allowed_size(self, local_path):
        """ Checks that the file size does not exceed the maximum allowed size """
        info = self.about_disk()
        max_size = info['max_file_size']
        statinfo = os.stat(local_path)
        filesize_bytes = statinfo.st_size
        if filesize_bytes > max_size:
            return False
        else:
            return True


class Dispatcher(FileSystemEventHandler):
    def __init__(self, remote_dir, abs_observe_dir, cloud_api):
        super().__init__()
        self.remote_dir = remote_dir
        self.observe_dir = abs_observe_dir
        self.cloud_api = cloud_api

    def remove_empty_dirs(self, local_dir):
        logging.debug('Try remove empty dir: %s...', local_dir)
        
        if local_dir.startswith(os.path.abspath(self.observe_dir)+'/'):
            try:
                os.rmdir(local_dir)
            except OSError as err:
                if err.errno == errno.ENOTEMPTY:
                    logging.debug('not empty')
                else:
                    raise
        else:
            logging.debug('it is root dir. Abort')

    def get_remote_subdirs(self, path):
        remote_subdirs = path.replace(self.observe_dir, '')
        if remote_subdirs.startswith('/'):
            remote_subdirs = remote_subdirs[1:]
        if not remote_subdirs.endswith('/'):
            remote_subdirs + '/'
        return remote_subdirs

    def dispatch(self, event):
        logging.debug('dispatch (%s) event %s', event.event_type, event)

        if event.event_type == 'created':
            local_path = event.src_path

            if event.is_directory:
                remote_subdirs = self.get_remote_subdirs(local_path)
                remote_path = os.path.join(self.remote_dir, remote_subdirs)

                logging.debug('create dir %s...', local_path)
                self.cloud_api.create_dir(remote_path)
            else:
                local_dir, filename = os.path.split(local_path)
                remote_subdirs = self.get_remote_subdirs(local_dir)
                remote_path = os.path.join(self.remote_dir, remote_subdirs, filename)

                logging.debug('posting file %s...', local_path)
                self.cloud_api.post_file(remote_path, local_path)
                self.remove_empty_dirs(local_dir)


class RabbitHole(Daemon):
    def run(self):
        load_config()
        start()


def load_config():
    config.read('{}/.config/rabbithole.ini'.format(home_dir))


def start():
    try:
        for observe_dir in config.sections():
            conf = config[observe_dir]
            abs_observe_dir = os.path.expanduser(observe_dir)
            if os.path.exists(abs_observe_dir):
                remote_dir = conf['remote_dir']
                cloud = conf['cloud']
                if cloud == 'yandex':
                    token = conf['token']
                    cloud_api = YandexApi(token)
                else:
                    raise KeyError

                observer = Observer()
                dispatcher = Dispatcher(remote_dir, abs_observe_dir, cloud_api)
                observer.schedule(dispatcher, abs_observe_dir, recursive=True)
                observer.start()
                logging.info('Watching {}'.format(abs_observe_dir))
                observers.append(observer)

        while True:
            time.sleep(1)
    finally:
        stop()


def stop():
    for observer in observers:
        observer.unschedule_all()
        observer.stop()
        observer.join()


def print_help():
    print("""start, stop, reload (restart)
    Get new token for Yandex.Disk: https://oauth.yandex.ru/authorize?response_type=token&client_id={}
    """.format(YandexApi.client_id))


if __name__ == '__main__':
    if len(sys.argv) > 1:
        rh = RabbitHole(pidfile)
        command = sys.argv[1]

        if command == 'start':
            rh.start()
        elif command == 'stop':
            rh.stop()
        elif command in ('reload', 'restart'):
            rh.restart()
        else:
            print_help()
    else:
        load_config()
        start()
