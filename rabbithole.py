#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
token
dir_path
remote_dir
"""

import requests
# from requests_toolbelt import MultipartEncoder, MultipartEncoderMonitor
# from clint.textui.progress import Bar as ProgressBar
# from clint.textui import colored as c
from os import listdir, remove, unlink
from os.path import isfile, join, expanduser
import configparser
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import daemon
import time
import sys




home_dir = expanduser("~")
config = configparser.ConfigParser()
config.read('{}/.config/rabbithole.ini'.format(home_dir))

pidfile = "/var/run/user/1000/rabbithole.pid"



# def create_callback(encoder, filename):
#     encoder_len = encoder.len / 1024.0 / 1024.0
#     _label = '{} (MB)'.format( c.blue(filename, bold=True) )
#     bar = ProgressBar(
#         expected_size=encoder_len, 
#         filled_char=c.yellow('='), 
#         label=_label, 
#         hide=False
#     )

#     def callback(monitor):
#         bar.show(monitor.bytes_read / 1024.0 / 1024.0)

#     return callback


def set_lockfile():
    pid = str(os.getpid())
    with open(pidfile, 'w') as f:
        f.write(pid)


def check_lockfile():
    if os.path.exists(pidfile):
        print('Another instance work. Aborting...')
        sys.exit()


class YandexApi(object):
    host = 'https://cloud-api.yandex.net'
    version = 'v1'
    client_id = '14e6df77206c47ab8d4e0414503ed242'
    # token = 'AQAAAAAFBsgnAARGFTEalhFRb0X1mTWPuMuFoPQ'

    headers = {
        'Authorization': 'OAuth {}'.format(token),
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }

    def __init__(self, token):
        self.token = token

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

        # print('{}: {}->{}'.format(r, local_path, path))

        if r.status_code == 201:
            remove(local_path)

    # def post_file2(self, path, local_path, filename):
    #     put_url = self._get_url_for_post_file(path)
    #     # print('prepare')
    #     e = MultipartEncoder(
    #         fields={'file': (filename, open(local_path, 'rb'), 'text/plain')}
    #     )
    #     callback = create_callback(e, filename)
    #     m = MultipartEncoderMonitor(e, callback)
    #     # print('sending')
    #     r = requests.put(put_url, data=m, headers={'Content-Type': m.content_type})

    #     if r.status_code == 201:
    #         print("\nDone[{}]: {} -> {}".format(
    #             c.green(r.status_code), 
    #             local_path, 
    #             path
    #         ))
    #         os.remove(local_path)
    #     else:
    #         print("\nError[{}]: {} -> {}: {}".format(
    #             c.red(r.status_code), 
    #             local_path, 
    #             path,
    #             r.json()
    #         ))


class Dispatcher(FileSystemEventHandler):
    def __init__(self, remote_dir, cloud_api):
        super().__init__()
        self.remote_dir = remote_dir
        self.cloud_api = cloud_api

    def dispatch(self, event):
        if event.event_type == 'created' and not event.is_directory:
            local_path = event.src_path
            local_dir, filename = os.path.split(local_path)
            remote_path = join(self.remote_dir, file_name)
            self.cloud_api.post_file(remote_path, local_path)


# yd = YandexApi()
# yd.about_disk()
# yd.post_file('/testfile', './rabbithole.py')


# dir_path = '/home/freezeman/rabbithole'
# onlyfiles = [f for f in os.listdir(dir_path) if isfile(join(dir_path, f))]

# if len(sys.argv) > 1:
#     remote_dir = sys.argv[1]
# else:
#     remote_dir = '/'

# for file_name in onlyfiles:
#     filepath = join(dir_path, file_name)
#     remote_path = join(remote_dir, file_name)
#     yd.post_file2(remote_path, filepath, file_name)


if __name__ == '__main__':
    check_lockfile()

    context = daemon.DaemonContext(
        working_directory=script_dir,
        detach_process=True,
        # files_preserve=[logging.root.handlers[0].stream.fileno()],
    )

    with context:
        set_lockfile()

        for observe_dir in config:
            # check_exist_files()
            remote_dir = config[observe_dir]['remote_dir']
            cloud = config[observe_dir]['cloud']
            if cloud == 'yandex':
                token = config[observe_dir]['token']
                cloud_api = YandexApi(token)

            observer = Observer()
            dispatcher = Dispatcher(remote_dir, cloud_api)
            observer.schedule(dispatcher, observe_dir, recursive=False)
            observer.start()

            try:
                while True:
                    time.sleep(1)
            finally:
                observer.stop()
                observer.join()
                os.unlink(pidfile)
    