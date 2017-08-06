#!/usr/bin/python3
# -*- coding: utf-8 -*-

import requests
import os
import configparser
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from daemon import Daemon
import time
import sys
import logging



home_dir = os.path.expanduser("~")
config = configparser.ConfigParser()
pidfile = '/var/run/user/1000/rabbithole.pid'
local_share_path = os.path.join(home_dir, '.local/share/rabbithole')
logfile = os.path.join(local_share_path, 'rabbithole.log')
os.makedirs(local_share_path, exist_ok=True)
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

    def __init__(self, token):
        self.token = token
        self.headers = {
            'Authorization': 'OAuth {}'.format(token),
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }

    def about_disk(self):
        logging.debug('Get cloud info')
        url = '{}/{}/disk/'.format(self.host, self.version)
        r = requests.get(url, headers=self.headers)
        data = r.json()

        if r.status_code != 200:
            logging.error('Failed to get cloud info: status_code=%d (%s)', r.status_code, r.reason)
            return None
        
        data['free_space'] = data['total_space'] - data['used_space']
        return data

    def _get_url_for_post_file(self, path):
        logging.debug('Get url for upload to %s', path)
        url = '{}/{}/disk/resources/upload'.format(self.host, self.version)
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

    def post_file(self, path, local_path):
        logging.debug('Transfer file %s to cloud', local_path)
        if self.enough_space(local_path) and self.allowed_size(local_path):
            put_url = self._get_url_for_post_file(path)
            if put_url:
                files = {'file': open(local_path, 'rb')}
                r = requests.put(put_url, files=files)

                if r.status_code == 201:
                    os.remove(local_path)
                else:
                    logging.error('Upload failed: status_code=%d (%s)', r.status_code, r.reason)

                return r.status_code
        else:
            logging.error('The file size is more valid or there is insufficient free space in the cloud.')
            return -1

    def enough_space(self, local_path):
        info = self.about_disk()
        free_space = info['free_space']
        statinfo = os.stat(local_path)
        filesize_bytes = statinfo.st_size
        if free_space > filesize_bytes:
            return True
        else:
            return False

    def allowed_size(self, local_path):
        info = self.about_disk()
        max_size = info['max_file_size']
        statinfo = os.stat(local_path)
        filesize_bytes = statinfo.st_size
        if filesize_bytes > max_size:
            return False
        else:
            return True


class Dispatcher(FileSystemEventHandler):
    def __init__(self, remote_dir, cloud_api):
        super().__init__()
        self.remote_dir = remote_dir
        self.cloud_api = cloud_api

    def dispatch(self, event):
        if event.event_type == 'created' and not event.is_directory:
            logging.debug('dispatch event %s', event)
            self.local_path = local_path = event.src_path
            local_dir, filename = os.path.split(local_path)
            self.remote_path = os.path.join(self.remote_dir, filename)
            logging.debug('posting file %s...', local_path)
            self.cloud_api.post_file(self.remote_path, self.local_path)


class RabbitHole(Daemon):
    def run(self):
        load_config()
        start()


def load_config():
    config.read('{}/.config/rabbithole.ini'.format(home_dir))


def start():
    for observe_dir in config.sections():
        conf = config[observe_dir]
        abs_observe_dir = os.path.expanduser(observe_dir)
        if os.path.exists(abs_observe_dir):
            remote_dir = conf['remote_dir']
            cloud = conf['cloud']
            if cloud == 'yandex':
                token = conf['token']
                cloud_api = YandexApi(token)

            observer = Observer()
            dispatcher = Dispatcher(remote_dir, cloud_api)
            observer.schedule(dispatcher, abs_observe_dir, recursive=False)
            observer.start()
            logging.info('Watching {}'.format(abs_observe_dir))
            observers.append(observer)

    try:
        while True:
            time.sleep(1)
    finally:
        stop()


def stop():
    for observer in observers:
        observer.stop()
        observer.join()


def print_help():
    print("""start, stop, reload
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
