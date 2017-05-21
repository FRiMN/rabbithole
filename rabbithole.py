#!/usr/bin/python3
# -*- coding: utf-8 -*-

import requests
from os import listdir, remove
from os.path import isfile, join
import sys



class YandexApi(object):
    host = 'https://cloud-api.yandex.net'
    version = 'v1'
    client_id = '14e6df77206c47ab8d4e0414503ed242'
    client_password = '5470b6389f164204a61e3c5ba13eb320'
    token = 'AQAAAAAFBsgnAARGFZoAKbVaNkRErA0rDihDjbw'

    headers = {
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
            'overwrite': 'true',
        }
        r = requests.get(url, headers=self.headers, params=payload)
        data = r.json()

        return data['href']

    def post_file(self, path, local_path):
        put_url = self._get_url_for_post_file(path)
        files = {'file': open(local_path, 'rb')}
        r = requests.put(put_url, files=files)

        print('{}: {}->{}'.format(r, local_path, path))

        if r.status_code == 201:
            remove(local_path)


yd = YandexApi()
# yd.about_disk()
# yd.post_file('/testfile', './rabbithole.py')


dir_path = '/home/freezeman/rabbithole'
onlyfiles = [f for f in listdir(dir_path) if isfile(join(dir_path, f))]

if len(sys.argv) > 1:
    remote_dir = sys.argv[1]
else:
    remote_dir = '/'

for file_name in onlyfiles:
    filepath = join(dir_path, file_name)
    remote_path = join(remote_dir, file_name)
    yd.post_file(remote_path, filepath)
    