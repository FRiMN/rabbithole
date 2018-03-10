#!/usr/bin/python3
# -*- coding: utf-8 -*-

import re
import requests
import os
import errno
import configparser
import time
import sys
import logging
from multiprocessing import Manager
from multiprocessing.pool import Pool

from daemon import Daemon



home_dir = os.path.expanduser("~")
config = configparser.ConfigParser()
uid = os.getuid()
pidfile = '/var/run/user/{:d}/rabbithole.pid'.format(uid)
local_share_path = os.path.join(home_dir, '.local/share/rabbithole')
logfile = os.path.join(local_share_path, 'rabbithole.log')
os.makedirs(local_share_path, exist_ok=True)
# list of active observers
observers = []
default_processes_per_observer = 4
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

    def __init__(self, token, observe_dir, pass_files, remote_dir):
        self.token = token
        self.headers = {
            'Authorization': 'OAuth {}'.format(token),
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        self.observe_dir = observe_dir
        self.pass_files = pass_files
        self.remote_dir = remote_dir

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

    def _get_url_for_post_file(self, remote_path, dry=True):
        logging.debug('Get url for upload to %s', remote_path)
        url = '{}/disk/resources/upload'.format(self.prefix)
        payload = {
            'path': remote_path,
            'overwrite': 'false',
        }
        r = requests.get(url, headers=self.headers, params=payload)
        data = r.json()

        if r.status_code == 200:
            return data['href']
        elif r.status_code == 409 and not dry:
            logging.info(data['description'])
            remote_dir_path = os.path.dirname(remote_path)
            if self.create_dir(remote_dir_path):
                return self._get_url_for_post_file(remote_path)
            else:
                return None
        else:
            logging.error(data['description'])
            return None

    @staticmethod
    def total_logging(secs, filesize_bytes, remote_path, local_path):
        mbs = filesize_bytes / 1024 / 1024 / secs
        if mbs > 1:
            logging.debug('Done: %f sec, %f MB/s (%s, %s)', secs, mbs, remote_path, local_path)
        else:
            kbs = filesize_bytes / 1024 / secs
            logging.debug('Done: %f sec, %f KB/s (%s, %s)', secs, kbs, remote_path, local_path)

    def post_file(self, remote_path, local_path):
        logging.debug('Transfer file %s to cloud', local_path)
        if self.enough_space(local_path) and self.allowed_size(local_path):
            put_url = self._get_url_for_post_file(remote_path, dry=False)
            if put_url:
                files = {'file': open(local_path, 'rb')}
                r = requests.put(put_url, files=files)

                if r.status_code == 201:
                    filesize_bytes = os.path.getsize(local_path)
                    if r.elapsed:
                        ts = r.elapsed.total_seconds()
                        self.total_logging(ts, filesize_bytes, remote_path, local_path)
                    os.remove(local_path)
                    local_dirs = os.path.dirname(local_path)
                    remove_empty_dirs(local_dirs, self.observe_dir)
                else:
                    logging.error('Upload failed: status_code=%d (%s)', r.status_code, r.reason)

                return True
            else:
                self.pass_files.append(local_path)
                return False
        else:
            logging.error('The file size is more valid or there is insufficient free space in the cloud.')
            self.pass_files.append(local_path)
            return False

    def create_dir(self, path):
        if path[0] == '/':
            path = path[1:]
        path_list = path.split('/')
        sub_path = '/'.join(path_list[:-1])
        if self.remote_dir[1:] != sub_path:
            self.create_dir(sub_path)

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
        return free_space > filesize_bytes

    def allowed_size(self, local_path):
        """ Checks that the file size does not exceed the maximum allowed size """
        info = self.about_disk()
        max_size = info['max_file_size']
        statinfo = os.stat(local_path)
        filesize_bytes = statinfo.st_size
        return filesize_bytes <= max_size


class RabbitHole(Daemon):
    def run(self):
        load_config()
        start()


def load_config():
    config.read('{}/.config/rabbithole.ini'.format(home_dir))


def remove_empty_dirs(local_dir, observe_dir):
    logging.debug('Try remove empty dir: %s...', local_dir)

    if local_dir.startswith(observe_dir) and len(local_dir) > len(observe_dir):
        try:
            os.rmdir(local_dir)
            path_list = local_dir.split('/')
            sub_path = '/'.join(path_list[:-1])
            remove_empty_dirs(sub_path, observe_dir)
        except OSError as err:
            if err.errno == errno.ENOTEMPTY:
                logging.debug('%s not empty', local_dir)
            else:
                raise
    else:
        logging.debug('it is root dir. Abort')


def start():
    with Manager() as manager:
        # list files for passing
        pass_files = manager.list([])

        try:
            watching_dirs = {}
            for observe_dir in config.sections():
                conf = config[observe_dir]
                abs_observe_dir = os.path.expanduser(observe_dir)

                # Избавляемся от лишнего слэша в конце
                if abs_observe_dir.endswith('/'):
                    abs_observe_dir = os.path.dirname(abs_observe_dir)

                if os.path.exists(abs_observe_dir):
                    remote_dir = conf['remote_dir']
                    cloud = conf['cloud']
                    if cloud == 'yandex':
                        token = conf['token']
                        cloud_api = YandexApi(token, abs_observe_dir, pass_files, remote_dir)
                    else:
                        raise KeyError

                    logging.info('Watching {}'.format(abs_observe_dir))
                    watching_dirs[abs_observe_dir] = dict(
                        cloud_api=cloud_api,
                    )

            while True:
                for watching_dir in watching_dirs.keys():
                    wo = watching_dirs[watching_dir]
                    cloud_api = wo['cloud_api']
                    params = []
                    for (dirpath, dirnames, filenames) in os.walk(watching_dir):
                        for filename in filenames:
                            local_path = os.path.join(dirpath, filename)
                            if local_path in pass_files:
                                continue
                            remote_sub_path = re.sub('^{}'.format(watching_dir), '', dirpath, count=1)
                            remote_sub_path = re.sub('^\/', '', remote_sub_path, count=1)
                            remote_path = os.path.join(cloud_api.remote_dir, remote_sub_path, filename)

                            params.append((remote_path, local_path))
                    if params:
                        with Pool(default_processes_per_observer) as p:
                            p.starmap(cloud_api.post_file, params)

                time.sleep(1)
        finally:
            stop()


def stop():
    logging.info('Stop')


def print_help():
    print("""start, stop, restart
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
        elif command == 'restart':
            rh.restart()
        else:
            print_help()
    else:
        load_config()
        start()
