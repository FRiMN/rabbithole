#!/usr/bin/python3
# -*- coding: utf-8 -*-

import requests
import os
import configparser
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import sys



home_dir = os.path.expanduser("~")
config = configparser.ConfigParser()
config.read('{}/.config/rabbithole.ini'.format(home_dir))



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

        print(r.json())

        self.total_space = data['total_space']
        self.used_space = data['used_space']
        self.free_space = self.total_space - self.used_space

        print(self.free_space)

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
            print(data)
            sys.exit()

    def post_file(self, path, local_path):
        put_url = self._get_url_for_post_file(path)
        files = {'file': open(local_path, 'rb')}
        r = requests.put(put_url, files=files)

        if r.status_code == 201:
            os.remove(local_path)


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


def main():
    observers = []

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
        for observer in observers:
            observer.stop()
            observer.join()


if __name__ == '__main__':
    main()
