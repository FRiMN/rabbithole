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



home_dir = os.path.expanduser("~")
config = configparser.ConfigParser()
pidfile = '/var/run/user/1000/rabbithole.pid'
observers = []



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
        url = '{}/{}/disk/'.format(self.host, self.version)
        r = requests.get(url, headers=self.headers)
        data = r.json()
        data['free_space'] = data['total_space'] - data['used_space']
        return data

    def _get_url_for_post_file(self, path):
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
            print(data['description'])
            return None

    def post_file(self, path, local_path):
        if self.enough_space(local_path) and self.allowed_size(local_path):
            put_url = self._get_url_for_post_file(path)
            if put_url:
                files = {'file': open(local_path, 'rb')}
                r = requests.put(put_url, files=files)

                if r.status_code == 201:
                    os.remove(local_path)
        else:
            print('The file size is more valid or there is insufficient free space in the cloud.')

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
            local_path = event.src_path
            local_dir, filename = os.path.split(local_path)
            remote_path = os.path.join(self.remote_dir, filename)
            self.cloud_api.post_file(remote_path, local_path)


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
        remote_dir = conf['remote_dir']
        cloud = conf['cloud']
        if cloud == 'yandex':
            token = conf['token']
            cloud_api = YandexApi(token)

        observer = Observer()
        dispatcher = Dispatcher(remote_dir, cloud_api)
        observer.schedule(dispatcher, abs_observe_dir, recursive=False)
        observer.start()
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
    print("""start, stop, reload""")


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
