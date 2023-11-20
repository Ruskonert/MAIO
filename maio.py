#!/usr/bin/env python3
import os
import sys
import argparse
import logging
import threading
import json
import time
import socket

# global log handler, will be initialize later
LOG : logging.Logger = None


# MAIO Configuration is contains as follows
MAIO_REMOTE_PORT : int = 40505

MAIO_SYSTEM_TYPE_MONITOR = 0
MAIO_SYSTEM_TYPE_SENSOR = 1

MAIO_REMOTE_MAX_CONNECTION = 10

MAIO_MSG_INIT = 0
MAIO_MSG_RECORD_TOP = 1
MAIO_MSG_RECORD_PROCESS = 2
MAIO_MSG_RECORD_SAR = 3

MAIO_MSG_SEND_TOP = 4
MAIO_MSG_SEND_PROCESS = 5
MAIO_MSG_SEND_SAR = 6

MAIO_MSG_TERMINATED = 7

class MAIOMessage:
    def __init__(self, type : int, peer : socket.socket, data):
        self.type = type
        self.peer = peer
        self.data = data

    @staticmethod
    def is_vaild_message(letter):
        return letter == bytes.fromhex('4d41494f5f4d4f4e49544f52').decode() # MAIO_MONITOR
    
    @staticmethod
    def _maio_build_msg_init(filename):
        data = {}
        script_code = open(sys.argv[0], 'r').read()
        data['script'] = script_code
        data['filename'] = filename
        return MAIOMessage(MAIO_MSG_INIT, None, data)
    
    @staticmethod
    def _maio_msg_init(handler, peer, data):
        LOG.info(f"Sensor HELLO")
        if not hasattr(sys, 'getwindowsversion'):
           return "This sensor is not linux/unix like"
        else:
            _tmp_name = data['filename']
            _code = data['script']
            LOG.debug(f"Monitor Hello & MAIO script was received, filename={len(_tmp_name)}, bytes={len(_code)}")
            _f = open(f"{_tmp_name}", 'w')
            _f.write(_code)
            _f.close()
        return MAIOMessage(MAIO_MSG_INIT, peer, data)

    @staticmethod
    def _maio_build_msg_record_top(filepath):
        data = {}
        elements = open(filepath, 'r').read().split("\n")
        for element in elements:
            _split_data = element.split(" ")
            if len(_split_data) == 0:
                continue

            if len(_split_data) > 1:
                data[_split_data[0]] = _split_data[1:]
            else:
                data[_split_data[0]] = []
    
        return MAIOMessage(MAIO_MSG_SEND_TOP, None, data)
    
    
    @staticmethod
    def _maio_msg_record_top(handler, peer, data):
        result = {}
        result_cmdline = {}
        for dir_entry in os.scandir("/proc"):
            tid_entries = []
            try:
                pid = int(dir_entry.path.replace("/proc/", ""))
                command_line = ''
                with open(f"/proc/{pid}/cmdline", 'r') as f:
                    command_line = f.read().split("\x00")[:-1]
                    f.close()

                try:
                    for tid_entry in os.scandir(f"/proc/{pid}/task"):
                        tid_number = tid_entry.path.replace(f"/proc/{pid}/task/", "")
                        if tid_number != str(pid):
                            tid_entries.append(tid_number)
                except FileNotFoundError:
                    # maybe it has not TID
                    pass

                # except PID
                if len(tid_entries) > 0:
                    result[str(pid)] = tid_entries
                else:
                    result[str(pid)] = []

                result_cmdline[str(pid)] = command_line
                    
            except ValueError:
                # it is not specific pid, others.
                continue
        
        for pid in result.keys():
            tids = result.get(pid, None)
            if tids == None:
                # already removed or filtered.
                continue

            for tid in tids:
                if tid in result.keys():
                    del result[tid]
                    del result_cmdline[tid]
        
        maio_data = {}

        # key is process name & value is list of command line
        for match_process_name, match_command_line in data.items():
            equals = False
            for pids in result_cmdline.keys():
                cmds = result_cmdline[pids]

                # it is system proc, not normal process.
                if len(cmds) == 0:
                    continue

                if match_process_name == cmds[0]:
                    if len(cmds) > 1:
                        left = ''.join(match_command_line).lower()
                        right = ''.join(cmds[1:]).lower()
                        if left == right:
                            equals = True
                            break
                    else:
                        equals = True
                        break

            if equals:
                maio_data[pids] = {
                    "TIDS": result[pids],
                    "CMDS": cmds
                }
                break
            else:
                LOG.warning(f"No found match the process with arguments, process_name={match_process_name}, args={match_command_line}")
        if len(maio_data) > 0:
            LOG.debug(f"Dissected process PID/TID & arguments -> {maio_data}")
        return MAIOMessage(MAIO_MSG_SEND_TOP, peer, maio_data)
    

    @staticmethod
    def _maio_msg_record_process(handler, peer, data):
        pass

    @staticmethod
    def _maio_msg_record_sar(handler, peer, data):
        pass

    @staticmethod
    def _maio_msg_terminated(handler, peer, data):
        pass

    @staticmethod
    def decode(handler, peer, bytes):
        LOG.debug(f"recv by remote peer, bytes={bytes}")
        _monitor_vaildate = {
            MAIO_MSG_RECORD_TOP: None,
            MAIO_MSG_RECORD_PROCESS: None,
            MAIO_MSG_RECORD_SAR: None,
            MAIO_MSG_SEND_TOP: None,
            MAIO_MSG_SEND_PROCESS: None,
            MAIO_MSG_SEND_SAR: None,
            MAIO_MSG_TERMINATED: MAIOMessage._maio_msg_terminated,
        }

        _sensor_vaildate = {
            MAIO_MSG_INIT: MAIOMessage._maio_msg_init,
            MAIO_MSG_RECORD_TOP: None,
            MAIO_MSG_RECORD_PROCESS: None,
            MAIO_MSG_RECORD_SAR: None,
            MAIO_MSG_SEND_TOP: MAIOMessage._maio_msg_record_top,
            MAIO_MSG_SEND_PROCESS: None,
            MAIO_MSG_SEND_SAR: None,
            MAIO_MSG_TERMINATED: MAIOMessage._maio_msg_terminated,
        }

        dct = None
        try:
            dct = json.loads(bytes)
        except json.JSONDecodeError as de:
            LOG.error(f"Can't decode JSON to MAIOMessage, detail={de}")
            return "Internal Error, it is not same structure"

        if not MAIOMessage.is_vaild_message(dct['iden']):
            return "Invaild MAIO Message"

        delegate = None
        if handler.type == MAIO_SYSTEM_TYPE_MONITOR:
            delegate = _monitor_vaildate.get(dct['type'])
        else:
            delegate = _sensor_vaildate.get(dct['type'])    

        if delegate == None:
            return f"It is not supported function, type={dct['type']}, forward_type={handler.type}"        
        else:
            return delegate(handler, peer, dct['data'])
    
    def to_string(self):
        dct = {}
        dct['iden'] = bytes.fromhex('4d41494f5f4d4f4e49544f52').decode()
        dct['type'] = self.type
        dct['data'] = self.data
        return json.dumps(dct)
    

class MAIORemoteHandler:
    def __init__(self, type : int, with_mont_addr: str = None, with_ssh = None):
        ip_addr = socket.gethostbyname(socket.gethostname())
        sock = None
        if type == MAIO_SYSTEM_TYPE_MONITOR:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("0.0.0.0", MAIO_REMOTE_PORT))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock = sock
        self._self_addr = ip_addr
        self.type = type
        self._monitor_addr = with_mont_addr
        self._pending = []
        self._with_ssh = with_ssh
        self._terminated = False
        self._worker = None
        self._lock = threading.Lock()
        self._peer_jobs = []

    def execute(self) -> bool:
        if self.type == MAIO_SYSTEM_TYPE_MONITOR:
            self._worker = threading.Thread(target=maio_intl_run_monitor, args=(self,))
        else:
            self._worker = threading.Thread(target=maio_intl_run_sensor, args=(self,))
        self._worker.daemon = True
        self._worker.start()
        """
        insert some code when successfully execute
        """
        return True
    
    def try_terminate(self):
        self._terminated = True

    def poll(self):
        rslt = None
        self._lock.acquire()
        if len(self._pending) == 0:
            self._lock.release()
            return None
        rslt = self._pending.pop()
        self._lock.release()
        return rslt


def maio_intl_msg_dissect(handler, peer, bytes):
    maio_object = MAIOMessage.decode(handler, peer, bytes)
    # it is error message due to raise some error
    if isinstance(maio_object, str):
        LOG.error(f"It is not vaild MAIO message, byte_len={len(bytes)}, reason={maio_object}")
        return False
    elif isinstance(maio_object, MAIOMessage):
        handler._lock.acquire()
        handler._pending.append(maio_object)
        handler._lock.release()
        return True


def maio_intl_delegate_th(handler : MAIORemoteHandler, socket : socket.socket):
    LOG.debug(f"Created new thread for delegate data, tid={threading.get_ident()}, from={socket.getpeername()}")

    msg = MAIOMessage._maio_build_msg_record_top("process_list.txt")
    socket.send(msg.to_string().encode())

    try:
        while True:
            if handler._terminated:
                break
            data = socket.recv(65535)
            if len(data) == 0:
                LOG.warning(f"sensor was disconnected, tid={threading.get_ident()}, target={socket.getpeername()}")
                break
            maio_intl_msg_dissect(handler, socket, data)
    except:
        LOG.warning(f"terminated peer, tid={threading.get_ident()}, target={socket.getpeername()}")


def maio_intl_run_monitor(handler : MAIORemoteHandler):
    """
    """
    handler._sock.listen(MAIO_REMOTE_MAX_CONNECTION)
    LOG.debug(f"Created new thread for monitoring, tid={threading.get_ident()}, binded to *:{MAIO_REMOTE_PORT}")

    ######## ssh is enabled so try upload this file
    if handler._with_ssh:
        try:
            import scp
            try:
                with scp.SCPClient(handler._with_ssh.get_transport()) as scp:
                    scp.put(sys.argv[0], "/tmp/maio_sensor.py", preserve_times=True)
                handler._with_ssh.exec_command(f'cd /tmp && python3 /tmp/maio_sensor.py -s 1 -i {handler._self_addr}')           
            except scp.SCPException as e:
                LOG.error(f"File upload using SCP failed, reason={e}")
        except ImportError:
            LOG.error(f"The scp module is not installed, skipping remote execution")
    ########


    while True:
        if handler._terminated:
            break
        client_sock, _ = handler._sock.accept()
        LOG.info(f"Connected to the monitor daemon, forward={client_sock.getpeername()} -> {client_sock.getsockname()}")
        thread_obj = threading.Thread(target=maio_intl_delegate_th, args=(handler, client_sock))
        thread_obj.daemon = True
        thread_obj.start()
        handler._peer_jobs.append(thread_obj)


def maio_intl_run_sensor(handler : MAIORemoteHandler):
    """
    """
    LOG.info(f"Created new thread for client, tid={threading.get_ident()}, connecting to {handler._monitor_addr}:{MAIO_REMOTE_PORT}")
    try:
        handler._sock.connect((handler._monitor_addr, MAIO_REMOTE_PORT))
        LOG.info("Connected.")
        while True:
            if handler._terminated:
                break
            
            data = handler._sock.recv(65535)
            if len(data) == 0:
                LOG.warning(f"monitor was disconnected, target={handler._sock.getpeername()}")
                break

            if not maio_intl_msg_dissect(handler, None, data):
                handler.try_terminate()

    except ConnectionRefusedError:
        LOG.error(f"Please check the monitoring device, maybe it is not binded address")
        handler.try_terminate()
    except ConnectionResetError:
        LOG.warning(f"The connection was reset by monitor, terminating process")
        handler.try_terminate()
        

def maio_handle_logger(filename : str, logging_level : int) -> logging.Logger:
    """
    handle and initialize MAIO logging object
    """
    logger = logging.getLogger('maio-runtime')
    fomatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(funcName)s:%(lineno)s] %(message)s')
    fileHandler = logging.FileHandler(filename=filename)
    streamHandler = logging.StreamHandler()

    fileHandler.setFormatter(fomatter)
    streamHandler.setFormatter(fomatter)

    logger.addHandler(fileHandler)
    logger.addHandler(streamHandler)

    logger.setLevel(logging_level)
    return logger


def main_with_monitor(args) -> MAIORemoteHandler:
    ########### Connecting SSH channel (given IP), it is option
    ssh = None
    if args.ip != None:
        remote_ip = args.ip
        remote_port = 22
        if ":" in args.ip:
            _ip_split = args.ip.split(":")
            remote_ip = _ip_split[0]
            remote_port = int(_ip_split[1])
        username  = args.user
        password  = args.password
        _pw_masked = "*" * len(password)
        LOG.info(f"Connecting to -> {username}@{remote_ip}:{remote_port}, PASS={_pw_masked}")
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=remote_ip, port=remote_port, username=username, password=password)
            LOG.info("Connected SSH.")
        except ImportError as e:
            LOG.error(f"paramiko is not installed, skipping a process for delegate with SSH")
        except paramiko.AuthenticationException as e:
            LOG.error(f"SSH connection was failed, reason={e}")
            sys.exit(1)
    ###########
    return MAIORemoteHandler(MAIO_SYSTEM_TYPE_MONITOR, with_mont_addr=None, with_ssh=ssh)


def main_with_sensor(args) -> MAIORemoteHandler:
    monitor_ip = args.ip
    if monitor_ip is None:
        LOG.error("You need to input the monitor ip address when system type is sensor (usuge ip flag)!")
        return None
    return MAIORemoteHandler(MAIO_SYSTEM_TYPE_SENSOR, with_mont_addr=monitor_ip)


def main_wtih_arguments(args, system_type : int):
    maio_proc_handler = None
    if system_type == MAIO_SYSTEM_TYPE_MONITOR:
        maio_proc_handler = main_with_monitor(args)
    else:
        maio_proc_handler = main_with_sensor(args)
    if maio_proc_handler == None:
        LOG.error("MAIO Program handler was reutnred None, terminated!")
        return 1

    if maio_proc_handler.execute():
        while True:
            if maio_proc_handler._terminated:
                break
            rslt = maio_proc_handler.poll()
            if rslt == None:
                time.sleep(0.01)
            else:
                if rslt.type == MAIO_MSG_SEND_TOP:
                    LOG.info(f"successfully!! {rslt}")
                    
                continue
    else:
        LOG.error("MAIO Program handler was failed to execute job, terminated!")
        return 2


if __name__ == "__main__":
    """
    Initialize program and dissect arguments, pass to main function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--user', metavar='username', help="SSH username")
    parser.add_argument('-p', '--password', metavar='password', help="SSH password")
    parser.add_argument('-i', '--ip', metavar='IP:[port]', help="Remote or client IP (e.x., 192.168.2.4, 192. 168.4.110:2004, ...)")
    parser.add_argument('--log-level', help="Set logging level", default="DEBUG")
    parser.add_argument("-s", "--system-type", help="Set sensor mode (0=monitor, 1=sensor)", default="0")
    args, another_args = parser.parse_known_args()
    
    if len(another_args) > 0:
        args.listpath = another_args[0]

    log_level = logging._nameToLevel.get(args.log_level, logging.INFO)
    LOG = maio_handle_logger("./maio.log", log_level)
    system_type = int(args.system_type)

    LOG.info(f"MAIO started, log_level={logging.getLevelName(log_level)}, system_type={system_type}")
    LOG.debug(f"Given arguments: {args}")
    sys.exit(main_wtih_arguments(args, system_type))