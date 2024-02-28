#!/usr/bin/python3
# -*- coding: utf-8-
"""
Simple code to set a client receiving IP changes from the specified server
"""
import base64
import hashlib
import logging
import os
import pathlib
import socket
import sys
import urllib.request
from logging.handlers import RotatingFileHandler

HOST: str = 'host_or_ip_of_your_server'
PORT: int = 65432
USERNAME: str = 'entry_to_put_in_the_hosts_file_on_server_side'
PASSWORD: str = hashlib.md5(b'secret').hexdigest()
IP: str = ''

with urllib.request.urlopen('https://4.ident.me') as r:
    IP = r.read().decode('utf8')


def create_rotating_log(path: str, level: str) -> logging.Logger:
    """
    Create the logger with file rotation.
    :param path: the path of the main log file
    :param level: the log level as defined in logging module
    :return: the logger
    """
    result: logging.Logger = logging.getLogger("ip_synchronizer_client")
    path_obj: pathlib.Path = pathlib.Path(path)
    if not os.path.exists(path_obj.parent.absolute()):
        os.makedirs(path_obj.parent.absolute())
    if os.path.exists(path):
        with open(path, 'w', encoding='utf-8') as f:
            f.close()
    else:
        path_obj.touch()
    # noinspection Spellchecker
    formatter: logging.Formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler: logging.Handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    result.addHandler(console_handler)
    file_handler: logging.Handler = RotatingFileHandler(path, maxBytes=1024 * 1024 * 5, backupCount=5)
    # noinspection PyUnresolvedReferences
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    result.addHandler(file_handler)
    # noinspection PyUnresolvedReferences
    result.setLevel(level)
    return result


logger = create_rotating_log('/tmp/ip_synchronizer_client.log', 'INFO')
logger.info('IP synchronizer client IP: %s', IP)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.settimeout(5)
    command: str = USERNAME + '@' + PASSWORD + '|' + IP
    logger.info('Sending command: %s', command)
    s.sendall(base64.b64encode(command.encode('ascii')))
    data = s.recv(1024)
    logger.info( "Received: %s", data.decode('ascii'))
logger.info('IP synchronizer client stopped')
sys.exit(0)
