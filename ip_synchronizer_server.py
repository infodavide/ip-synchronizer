#!/usr/bin/python3
# -*- coding: utf-*-
import atexit
import base64
import hashlib
import logging
import os
import pathlib
import signal
import socket
import sys
import traceback
from logging.handlers import RotatingFileHandler

FILE: str = '/etc/hosts'
HOST: str = '0.0.0.0'
PORT: int = 65432
USERS = {
  'entry_to_put_in_the_hosts_file_on_server_side': hashlib.md5(b'secret').hexdigest()
}
active: bool = True


def create_rotating_log(path: str, level: str) -> logging.Logger:
    """
    Create the logger with file rotation.
    :param path: the path of the main log file
    :param level: the log level as defined in logging module
    :return: the logger
    """
    result: logging.Logger = logging.getLogger('ip_synchronizer_server')
    path_obj: pathlib.Path = pathlib.Path(path)
    if not os.path.exists(path_obj.parent.absolute()):
        os.makedirs(path_obj.parent.absolute())
    if os.path.exists(path):
        open(path, 'w').close()
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


def cleanup() -> None:
    global active, s
    active = False
    try:
        if s:
            s.close()
    except Exception:
        _, _, cleanup_traceback = sys.exc_info()
        traceback.print_tb(cleanup_traceback, limit=1, file=sys.stderr)


def signal_handler(sig=None, frame=None) -> None:
    cleanup()


def replace_in_file(username: str, ip: str) -> None:
    global logger
    written: bool = False
    with open(FILE, 'r') as f:
        lines = f.readlines()
    with open(FILE, 'w') as f:
        for line in lines:
            if not written and username in line:
                text: str = ip + ' ' + username + '\n'
                logger.log(logging.DEBUG, 'Writing: %s' % text)
                f.write(text)
                written = True
            else:
                f.write(line)


def process(conn, data: bytes) -> None:
    global logger
    logger.log(logging.DEBUG, 'Processing')
    command: str = base64.b64decode(data).decode('ascii')
    logger.log(logging.DEBUG, 'Parsing command: %s' % command)
    parts = command.split('|')
    logger.log(logging.DEBUG, 'Parts: %s' % repr(parts))
    if len(parts) == 2:
        authentication = parts[0].split('@')
        logger.log(logging.DEBUG, 'Authentication: %s' % repr(authentication))
        if len(authentication) == 2:
            username: str = authentication[0]
            password: str = authentication[1]
            if username in USERS and USERS[username] == password:
                ip = parts[1]
                logger.log(logging.INFO, 'IP synchronized for: %s to: %s' % (username, ip))
                replace_in_file(username, ip)
                logger.log(logging.INFO, 'Sending ACK')
                conn.sendall('0K\n'.encode('ascii'))
            else:
                logger.log(logging.DEBUG, 'Bad authentication for user: % ' % username)
        else:
            logger.log(logging.DEBUG, 'Invalid authentication: % ' % command)
    else:
        logger.log(logging.DEBUG, 'Invalid command: % ' % command)
    conn.sendall('BYE\n'.encode('ascii'))


atexit.register(signal_handler)
signal.signal(signal.SIGINT, signal_handler)
logger = create_rotating_log('/tmp/ip_synchronizer_server.log', 'INFO')
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    logger.log(logging.INFO, 'IP synchronizer server is now listening...')
    while active:
        try:
            conn, addr = s.accept()
            with conn:
                conn.settimeout(5)
                logger.log(logging.INFO, f"Connection with {addr}")
                try:
                    data = conn.recv(1024)
                    if not data:
                        break
                    process(conn, data)
                except Exception:
                    _, _, exc_traceback = sys.exc_info()
                    traceback.print_tb(exc_traceback, limit=1, file=sys.stderr)
                logger.log(logging.INFO, 'IP synchronizer server is still listening...')
        except Exception:
            _, _, main_traceback = sys.exc_info()
            traceback.print_tb(main_traceback, limit=1, file=sys.stderr)
logger.log(logging.INFO, 'IP synchronizer server stopped')
exit(0)
