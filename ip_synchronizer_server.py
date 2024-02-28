#!/usr/bin/python3
# -*- coding: utf-8-
"""
Simple server used to notify IP changes to the clients
"""
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


def cleanup() -> None:
    """
    Cleanup the instances and session
    """
    active = False
    try:
        if s:
            s.close()
    # pylint: disable=broad-exception-caught
    except Exception:
        _, _, cleanup_traceback = sys.exc_info()
        traceback.print_tb(cleanup_traceback, limit=1, file=sys.stderr)
    # pylint: enable=broad-exception-caught


# pylint: disable=missing-type-doc
def signal_handler(sig=None, frame=None) -> None:
    """
    Trigger the cleanup when program is exited
    :param sig: the signal
    :param frame: the frame
    """
    cleanup()
# pylint: enable=missing-type-doc


def replace_in_file(username: str, ip: str) -> None:
    """
    Update the IP address into the file
    :param username: the user name
    :param ip: the IP address
    """
    written: bool = False
    with open(FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    with open(FILE, 'w', encoding='utf-8') as f:
        for line in lines:
            if not written and username in line:
                text: str = ip + ' ' + username + '\n'
                logger.debug('Writing: %s', text)
                f.write(text)
                written = True
            else:
                f.write(line)


# pylint: disable=redefined-outer-name
def process(s: socket, d: bytes) -> None:
    """
    process the request
    :param s: the socket
    :param d: the date of the request
    """
    logger.debug('Processing')
    command: str = base64.b64decode(d).decode('ascii')
    logger.debug('Parsing command: %s', command)
    parts = command.split('|')
    logger.debug('Parts: %s', repr(parts))
    if len(parts) == 2:
        authentication = parts[0].split('@')
        logger.debug('Authentication: %s', repr(authentication))
        if len(authentication) == 2:
            username: str = authentication[0]
            password: str = authentication[1]
            if username in USERS and USERS[username] == password:
                ip = parts[1]
                logger.info('IP synchronized for: %s to: %s', username, ip)
                replace_in_file(username, ip)
                logger.info('Sending ACK')
                s.sendall('0K\n'.encode('ascii'))
            else:
                logger.debug('Bad authentication for user: %s', username)
        else:
            logger.debug('Invalid authentication: %s', command)
    else:
        logger.debug('Invalid command: %s', command)
    s.sendall('BYE\n'.encode('ascii'))
# pylint: enable=redefined-outer-name

atexit.register(signal_handler)
signal.signal(signal.SIGINT, signal_handler)
logger = create_rotating_log('/tmp/ip_synchronizer_server.log', 'INFO')
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    logger.info('IP synchronizer server is now listening...')
    while active:
        # pylint: disable=broad-exception-caught
        try:
            conn, addr = s.accept()
            with conn:
                conn.settimeout(5)
                logger.info('Connection with %s', addr)
                try:
                    data = conn.recv(1024)
                    if not data:
                        break
                    process(conn, data)
                except Exception:
                    _, _, exc_traceback = sys.exc_info()
                    traceback.print_tb(exc_traceback, limit=1, file=sys.stderr)
                logger.info('IP synchronizer server is still listening...')
        except Exception:
            _, _, main_traceback = sys.exc_info()
            traceback.print_tb(main_traceback, limit=1, file=sys.stderr)
        # pylint: enable=broad-exception-caught
logger.info('IP synchronizer server stopped')
sys.exit(0)
