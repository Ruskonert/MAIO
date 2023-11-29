#!/usr/bin/env python3
import os
import sys
import argparse
import logging
import copy
import threading
import json
import struct
import time
import socket

# global log handler, will be initialize later
LOG: logging.Logger = None


# MAIO Configuration is contains as follows
MAIO_REMOTE_PORT: int = 40505

MAIO_SYSTEM_TYPE_MONITOR = 0
MAIO_SYSTEM_TYPE_SENSOR = 1

MAIO_REMOTE_MAX_CONNECTION = 10


MAIO_MSG_INIT = 0
MAIO_MSG_RECORD_TOP = 1
MAIO_MSG_RECORD_SAR = 3
MAIO_MSG_REQUEST_TOP = 4
MAIO_MSG_REQUEST_PROCESS = 5
MAIO_MSG_REQUEST_SAR = 6
MAIO_MSG_TERMINATED = 7

MAIO_MSG_RECORD_PROCESS_REPORTED = 21
MAIO_MSG_RECORD_PROCESS_CAPTURED = 22
MAIO_MSG_RECORD_PROCESS_TERMINATED = 23


def maio_msg_print_message(type_n):
    target = {
        MAIO_MSG_INIT: "MAIO_MSG_INIT",
        MAIO_MSG_RECORD_TOP: "MAIO_MSG_RECORD_TOP",
        MAIO_MSG_RECORD_SAR: "MAIO_MSG_RECORD_SAR",
        MAIO_MSG_REQUEST_TOP: "MAIO_MSG_REQUEST_TOP",
        MAIO_MSG_REQUEST_PROCESS: "MAIO_MSG_REQUEST_PROCESS",
        MAIO_MSG_REQUEST_SAR: "MAIO_MSG_REQUEST_SAR",
        MAIO_MSG_TERMINATED: "MAIO_MSG_TERMINATED",
        MAIO_MSG_RECORD_PROCESS_REPORTED: "MAIO_MSG_RECORD_PROCESS_REPORTED",
        MAIO_MSG_RECORD_PROCESS_CAPTURED: "MAIO_MSG_RECORD_PROCESS_CAPTURED",
        MAIO_MSG_RECORD_PROCESS_TERMINATED: "MAIO_MSG_RECORD_PROCESS_TERMINATED",
    }
    return target.get(type_n, "UNKNOWN")


class MAIOMessage:
    def __init__(self, type: int, peer: socket.socket, data):
        self.type = type
        self.peer = peer
        self.data = data

    @staticmethod
    def is_vaild_message(letter):
        return (
            letter == bytes.fromhex("4d41494f5f4d4f4e49544f52").decode()
        )  # MAIO_MONITOR

    @staticmethod
    def _maio_msg_send_init(filename):
        data = {}
        script_code = open(sys.argv[0], "r").read()
        data["script"] = script_code
        data["filename"] = filename
        return MAIOMessage(MAIO_MSG_INIT, None, data)

    @staticmethod
    def _maio_msg_send_request_process(filepath):
        data = {}
        elements = open(filepath, "r").read().split("\n")
        for element in elements:
            _split_data = element.split(" ")
            if len(_split_data) == 0:
                continue

            if len(_split_data) > 1:
                data[_split_data[0]] = _split_data[1:]
            else:
                data[_split_data[0]] = []

        return MAIOMessage(MAIO_MSG_REQUEST_PROCESS, None, data)

    @staticmethod
    def _maio_msg_send_report_process(detected_data):
        data = {"records": detected_data}
        return MAIOMessage(MAIO_MSG_RECORD_PROCESS_REPORTED, None, data)

    @staticmethod
    def _maio_msg_send_capture_process(pid):
        data = {"pid": pid}
        return MAIOMessage(MAIO_MSG_RECORD_PROCESS_CAPTURED, None, data)

    @staticmethod
    def _maio_msg_send_capture_process_by_sensor(data):
        """
        nothing to do, there is packing the message.
        """
        return MAIOMessage(MAIO_MSG_RECORD_PROCESS_CAPTURED, None, data)

    @staticmethod
    def _maio_msg_recv_init(_, peer, data):
        LOG.info(f"Sensor HELLO")
        if not hasattr(sys, "getwindowsversion"):
            return "This sensor is not linux/unix like"
        else:
            _tmp_name = data["filename"]
            _code = data["script"]
            LOG.debug(
                f"Monitor Hello & MAIO script was received, filename={len(_tmp_name)}, bytes={len(_code)}"
            )
            _f = open(f"{_tmp_name}", "w")
            _f.write(_code)
            _f.close()
        return MAIOMessage(MAIO_MSG_INIT, peer, data)

    @staticmethod
    def _maio_msg_recv_request_process(_, peer, data):
        result = {}
        result_cmdline = {}
        for dir_entry in os.scandir("/proc"):
            tid_entries = []
            try:
                pid = int(dir_entry.path.replace("/proc/", ""))
                command_line = ""
                with open(f"/proc/{pid}/cmdline", "r") as f:
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
            found_pid = None
            for pids in result_cmdline.keys():
                cmds = result_cmdline[pids]

                # it is system proc, not normal process.
                if len(cmds) == 0:
                    continue

                if match_process_name == cmds[0]:
                    if len(cmds) > 1:
                        left = "".join(match_command_line).lower()
                        right = "".join(cmds[1:]).lower()
                        if left == right:
                            found_pid = pids
                            break
                    else:
                        found_pid = pids
                        break
            if found_pid:
                maio_data[found_pid] = {
                    "CMDS": result_cmdline[found_pid],
                    "PROCESS_NAME": cmds[0],
                    "TIDS": result[found_pid],
                }
            else:
                LOG.warning(
                    f"No found match the process with arguments, process_name={match_process_name}, args={match_command_line}"
                )
        if len(maio_data) > 0:
            LOG.debug(f"Dissected process PID/TID & arguments -> {maio_data}")
        return MAIOMessage(MAIO_MSG_REQUEST_PROCESS, peer, maio_data)

    @staticmethod
    def _maio_msg_recv_report_process(_, peer, data):
        return MAIOMessage(MAIO_MSG_RECORD_PROCESS_REPORTED, peer, data)

    @staticmethod
    def _maio_msg_recv_capture_process(_, peer, data):
        return MAIOMessage(MAIO_MSG_RECORD_PROCESS_CAPTURED, peer, data)

    @staticmethod
    def decode(handler, peer, bytes_total):
        LOG.debug(f"recv by remote peer, bytes_len={len(bytes_total)}")
        pos = 0
        result_value = []
        while True:
            if pos == len(bytes_total):
                break

            bytes = None
            if bytes_total[pos : pos + 4] == b"\x01\x02\x03\x04":
                pos += 4
                length = struct.unpack(">H", bytes_total[pos : pos + 2])[0]
                pos += 2
                bytes = bytes_total[pos : pos + length]
                pos += length

                if bytes_total[pos : pos + 4] != b"\x00\x00\x00\x00":
                    # truncated message ?
                    LOG.warning(
                        "MAIO Message is truncated, stopping dissect and report anyway."
                    )
                    return result_value
                else:
                    pos += 4
            else:
                LOG.warning(
                    "MAIO Message is truncated or invaild, stopping dissect and report anyway."
                )
                return result_value

            _monitor_vaildate = {
                MAIO_MSG_INIT: None,
                MAIO_MSG_RECORD_TOP: None,
                MAIO_MSG_RECORD_PROCESS_REPORTED: MAIOMessage._maio_msg_recv_report_process,  # general
                MAIO_MSG_RECORD_PROCESS_CAPTURED: MAIOMessage._maio_msg_recv_capture_process,  # general
                MAIO_MSG_RECORD_SAR: None,
                MAIO_MSG_REQUEST_TOP: None,
                MAIO_MSG_REQUEST_PROCESS: None,  # send only
                MAIO_MSG_REQUEST_SAR: None,
                # MAIO_MSG_TERMINATED: MAIOMessage._maio_msg_terminated,
            }

            _sensor_vaildate = {
                MAIO_MSG_INIT: None,
                MAIO_MSG_RECORD_TOP: None,
                MAIO_MSG_RECORD_PROCESS_REPORTED: MAIOMessage._maio_msg_recv_report_process,  # general
                MAIO_MSG_RECORD_PROCESS_CAPTURED: MAIOMessage._maio_msg_recv_capture_process,  # general
                MAIO_MSG_RECORD_SAR: None,
                MAIO_MSG_REQUEST_TOP: None,
                MAIO_MSG_REQUEST_PROCESS: MAIOMessage._maio_msg_recv_request_process,
                MAIO_MSG_REQUEST_SAR: None,
                # MAIO_MSG_TERMINATED: MAIOMessage._maio_msg_terminated,
            }

            dct = None
            try:
                dct = json.loads(bytes)
            except json.JSONDecodeError as de:
                LOG.error(f"Can't decode JSON to MAIOMessage, detail={de}")
                result_value.append("Internal Error, it is not same structure")

            if not MAIOMessage.is_vaild_message(dct["iden"]):
                result_value.append("Invaild MAIO Message")
                return []

            delegate = None
            if handler.type == MAIO_SYSTEM_TYPE_MONITOR:
                delegate = _monitor_vaildate.get(dct["type"])
            else:
                delegate = _sensor_vaildate.get(dct["type"])

            if delegate == None:
                result_value.append(
                    f"It is not supported function, type={dct['type']}, forward_type={handler.type}"
                )
            else:
                result_value.append(delegate(handler, peer, dct["data"]))
        return result_value

    def to_packet_string(self):
        dct = {}
        dct["iden"] = bytes.fromhex("4d41494f5f4d4f4e49544f52").decode()
        dct["type"] = self.type
        dct["data"] = self.data
        datas = json.dumps(dct)
        return (
            b"\x01\x02\x03\x04"
            + struct.pack(">H", len(datas))
            + datas.encode()
            + b"\x00\x00\x00\x00"
        )


class MAIOProcessRecorder:
    def __init__(
        self,
        sock,
        pid,
        workdir,
        systype,
        delay: int,
        program_cmd: list,
        sensor_with_tid,
        sensor_parent_pid: int = None,
    ):
        self._thread = None
        if sensor_parent_pid:
            self._ppid = sensor_parent_pid
            self.threaded = True
        else:
            self._ppid = None
            self.threaded = False
        self._pid = int(pid)
        self._tid = sensor_with_tid
        self.peer_sock = sock
        self.systype = systype
        self.workdir = workdir
        self._delay = delay
        self._started_date = time.time()
        self._log = []
        self._terminated = False
        self._lock = threading.Lock()
        self._cmds = program_cmd

    @staticmethod
    def start_record_process(self):
        def calculate_cpu_usage(pid):
            with open(f"/proc/{pid}/stat") as stat_file:
                stat_content = stat_file.read().split()
            utime = int(stat_content[13])
            stime = int(stat_content[14])
            total_time = utime + stime

            with open("/proc/uptime") as uptime_file:
                uptime = float(uptime_file.read().split()[0])
                uptime_file.close()

            num_processors = os.cpu_count()
            seconds_since_start = uptime
            cpu_usage_percentage = (
                total_time / (num_processors * seconds_since_start)
            ) * 100
            return cpu_usage_percentage

        def calculate_thread_cpu_usage(pid, thread_id):
            stat_path = f"/proc/{pid}/task/{thread_id}/stat"

            with open(stat_path) as stat_file:
                stat_content = stat_file.read().split()
                stat_file.close()

            utime = int(stat_content[13])
            stime = int(stat_content[14])
            total_time = utime + stime
            return total_time

        def calculate_relative_thread_cpu_usage(pid, thread_id: int):
            thread_cpu_times_start = calculate_thread_cpu_usage(pid, thread_id)
            time.sleep(0.5)
            thread_cpu_times_end = calculate_thread_cpu_usage(pid, thread_id)

            with open("/proc/stat") as stat_file:
                lines = stat_file.readlines()
                stat_file.close()
            system_cpu_times_start = [int(time) for time in lines[0].split()[1:]]

            time.sleep(0.5)

            with open("/proc/stat") as stat_file:
                lines = stat_file.readlines()
                stat_file.close()
            system_cpu_times_end = [int(time) for time in lines[0].split()[1:]]

            thread_cpu_usages = (
                (thread_cpu_times_end - thread_cpu_times_start)
                / (sum(system_cpu_times_end) - sum(system_cpu_times_start))
            ) * 100
            return thread_cpu_usages

        # relative_sleep_sec = self._delay
        relative_sleep_sec = self._delay - 1  # for calcing relative cpu usuge
        while True:
            if relative_sleep_sec > 0:
                time.sleep(relative_sleep_sec)
            if self._terminated:
                break
            try:
                status_data = None
                with open(f"/proc/{self._pid}/status", "r") as f:
                    status_data = f.read().split("\n")
                    f.close()

                all_found = False
                shr_value = None
                res_value = None
                virt_value = None
                for status_text in status_data:
                    if "RssShmem" in status_text:
                        shr_value = int(
                            status_text.replace("RssShmem:", "")
                            .replace("kB", "")
                            .replace(" ", "")
                        )

                    elif "VmRSS" in status_text:
                        res_value = int(
                            status_text.replace("VmRSS:", "")
                            .replace("kB", "")
                            .replace(" ", "")
                        )

                    elif "VmSize" in status_text:
                        virt_value = int(
                            status_text.replace("VmSize:", "")
                            .replace("kB", "")
                            .replace(" ", "")
                        )

                    if shr_value != None and res_value != None and virt_value != None:
                        all_found = True
                        break

                if all_found:
                    cpu_usage_percentage = None

                    # it is PID
                    if not self.threaded:
                        time.sleep(1)
                        cpu_usage_percentage = calculate_cpu_usage(self._pid)
                    # it is TID (Thread PID)
                    else:
                        cpu_usage_percentage = calculate_relative_thread_cpu_usage(
                            self._ppid, self._pid
                        )

                    result = {
                        "TIMESTAMP": time.time(),
                        "COMMAND": " ".join(self._cmds),
                        "VIRT": virt_value,
                        "RES": res_value,
                        "SHR": shr_value,
                        "%CPU": cpu_usage_percentage,
                    }
                    LOG.debug(f"Process resource stat is calcuated, result={result}")
                    self.insert(result)
                else:
                    LOG.error("Can't catch the performance data, terminate thread")
                    self.try_terminate()
            except IOError as ioe:
                LOG.error(
                    f"Can't read the PROC information, maybe it was terminated by OS, detail={ioe}"
                )
                self.try_terminate()
                continue

    @staticmethod
    def start_record_hit_process(self):
        while True:
            if self._terminated:
                proc_name = "_".join(self._cmds).replace("/", "_").replace("\\", "_")
                filename = f"{self.workdir}/{self._pid}_{proc_name}_{int(self._started_date)}.csv"
                LOG.info(
                    f"The reported filepath is {filename}, pid={self._pid}, started_date={self._started_date}"
                )
                return
            try:
                msg = MAIOMessage._maio_msg_send_capture_process(self._pid)
                self.peer_sock.send(msg.to_packet_string())
                time.sleep(self._delay)
                log_data = self.poll()
                LOG.debug(
                    f"Captured data received, len={len(log_data)}, pid={self._pid}, cmds={self._cmds}"
                )
                for result in log_data:
                    """
                    the data structure is following that:
                    {'TIMESTAMP': 1700643830.737748, 'COMMAND': 'PROCESS_NAME 5', 'VIRT': 6861552, 'RES': 5273544, 'SHR': 5167616, '%CPU': 0.0}
                    """
                    self.record_to_data(result)

            except ConnectionAbortedError:
                LOG.error(
                    f"The peer sensor is aborted, terminate record for PID {self._pid}, {self._cmds}, peer={self.peer_sock.getpeername()}"
                )
                self.try_terminate()
            except ConnectionResetError:
                LOG.error(
                    f"The peer sensor is disconnected, terminate record for PID {self._pid}, {self._cmds}, peer={self.peer_sock.getpeername()}"
                )
                self.try_terminate()

    def record_to_data(self, result):
        ts = result["TIMESTAMP"]
        command = result["COMMAND"]
        virt = result["VIRT"]
        res = result["RES"]
        shr = result["SHR"]
        cpu = result["%CPU"]
        proc_name = "_".join(self._cmds).replace("\\", "_").replace("/", "_")
        filename = (
            f"{self.workdir}/{self._pid}_{proc_name}_{int(self._started_date)}.csv"
        )
        if not os.path.exists(filename):
            with open(filename, "a") as f:
                f.write("TIMESTAMP,VIRT,RES,SHR,%CPU,COMMAND\n")
                f.close()

        with open(filename, "a") as f:
            f.write("{},{},{},{},{},{}\n".format(ts, virt, res, shr, cpu, command))
            f.close()

    def try_terminate(self):
        self._terminated = True

    def insert(self, result):
        self._lock.acquire()
        self._log.append(result)
        self._lock.release()

    def poll(self):
        self._lock.acquire()
        log = copy.deepcopy(self._log)
        self._log = []
        self._lock.release()
        return log

    def start(self):
        if self._thread != None:
            LOG.error(
                f"You tried to execute recorder which already started! pid={self._pid}, cmds={self._cmds}"
            )
        else:
            if self.systype == MAIO_SYSTEM_TYPE_MONITOR:
                self._thread = threading.Thread(
                    target=MAIOProcessRecorder.start_record_hit_process, args=(self,)
                )
                self._thread.daemon = True
                self._thread.start()
                LOG.info(
                    f"Stated hitting the record data of process, pid={self._pid}, cmds={self._cmds}"
                )
            else:
                self._thread = threading.Thread(
                    target=MAIOProcessRecorder.start_record_process, args=(self,)
                )
                self._thread.daemon = True
                self._thread.start()
                LOG.info(
                    f"Started generating the record data of process, pid={self._pid}, cmds={self._cmds}, threaded={self.threaded}, parent_pid={self._ppid}"
                )


class MAIORemoteHandler:
    def __init__(
        self,
        type: int,
        with_mont_addr: str = None,
        with_ssh=None,
        remote_port=MAIO_REMOTE_PORT,
        with_args=None,
    ):
        ip_addr = socket.gethostbyname(socket.gethostname())
        sock = None
        if type == MAIO_SYSTEM_TYPE_MONITOR:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("0.0.0.0", remote_port))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock = sock
        self._self_addr = ip_addr
        self.type = type
        self._bind_port = remote_port
        self._monitor_addr = with_mont_addr
        self._pending = []
        self._with_ssh = with_ssh
        self._records = []
        self._terminated = False
        self._worker = None
        self._given_args = with_args
        self._lock = threading.Lock()
        self._peer_jobs = []

    def execute(self) -> bool:
        if self.type == MAIO_SYSTEM_TYPE_MONITOR:
            self._worker = threading.Thread(
                target=maio_intl_run_monitor, args=(self, self._given_args)
            )
        else:
            self._worker = threading.Thread(
                target=maio_intl_run_sensor, args=(self, self._given_args)
            )
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


def maio_intl_create_proc_record(
    handler: MAIORemoteHandler, rslt: MAIOMessage, system_type: int, delay: int
):
    detected_data = rslt.data
    if len(detected_data) > 0:
        sensor_addr = None
        port = None
        working_dir = None
        if system_type == MAIO_SYSTEM_TYPE_MONITOR:
            detected_data = rslt.data["records"]  # recv by sensor
            # make working folder for sensor
            sensor_addr, port = rslt.peer.getpeername()
            working_dir = f"{sensor_addr}_{port}"
            os.mkdir(working_dir)

            for pid, d in detected_data.items():
                process_name = d["PROCESS_NAME"].replace("\\", "_").replace("/", "_")
                sub_working_dir = f"{working_dir}/{process_name}"
                os.mkdir(sub_working_dir)

                mpr = MAIOProcessRecorder(
                    rslt.peer,
                    pid,
                    sub_working_dir,
                    system_type,
                    delay,
                    d["CMDS"],
                    None,
                    None,
                )  # not need to TID, Parent ID (just monitor)
                mpr.start()
                handler._records.append(mpr)

                for tid in d["TIDS"]:
                    mpr = MAIOProcessRecorder(
                        rslt.peer,
                        tid,
                        sub_working_dir,
                        system_type,
                        delay,
                        d["CMDS"],
                        None,
                        None,
                    )  # not need to TID, Parent ID (just monitor)
                    mpr.start()
                    handler._records.append(mpr)
        else:
            for pid, d in detected_data.items():
                mpr = MAIOProcessRecorder(
                    handler._sock, pid, None, system_type, delay, d["CMDS"], d["TIDS"]
                )
                mpr.start()
                handler._records.append(mpr)

                for tid in d["TIDS"]:
                    mpr = MAIOProcessRecorder(
                        handler._sock,
                        tid,
                        None,
                        system_type,
                        delay,
                        d["CMDS"],
                        d["TIDS"],
                        pid,
                    )
                    mpr.start()
                    handler._records.append(mpr)
    else:
        LOG.warning(
            f"Catched record processes, but detected data is None, target={rslt.peer.getpeername()}"
        )


def maio_intl_msg_dissect(handler, peer, bytes):
    maio_object = MAIOMessage.decode(handler, peer, bytes)
    for maio_obj in maio_object:
        # it is error message due to raise some error
        if isinstance(maio_obj, str):
            LOG.error(
                f"It is not vaild MAIO message, byte_len={len(bytes)}, reason={maio_obj}"
            )
            return False
        elif isinstance(maio_obj, MAIOMessage):
            handler._lock.acquire()
            handler._pending.append(maio_obj)
            handler._lock.release()
            return True


def maio_intl_delegate_th(
    handler: MAIORemoteHandler, socket: socket.socket, target_list_path: str
):
    LOG.debug(
        f"Created new thread for delegate data, tid={threading.get_ident()}, from={socket.getpeername()}"
    )

    msg = MAIOMessage._maio_msg_send_request_process(target_list_path)
    socket.send(msg.to_packet_string())

    try:
        while True:
            if handler._terminated:
                break
            data = socket.recv(65535)
            while True:
                if data[-4:] == b"\x00\x00\x00\x00":
                    break
                # maybe it is truncated
                _data = socket.recv(65535)
                data = data + _data

            if len(data) == 0:
                LOG.warning(
                    f"sensor was disconnected, tid={threading.get_ident()}, target={socket.getpeername()}"
                )
                break
            maio_intl_msg_dissect(handler, socket, data)
    except:
        LOG.warning(
            f"terminated peer, tid={threading.get_ident()}, target={socket.getpeername()}"
        )


def maio_intl_run_monitor(handler: MAIORemoteHandler, args):
    """ """
    handler._sock.listen(MAIO_REMOTE_MAX_CONNECTION)
    LOG.debug(
        f"Created new thread for monitoring, tid={threading.get_ident()}, binded to *:{handler._bind_port}"
    )

    ######## ssh is enabled so try upload this file
    if handler._with_ssh:
        try:
            import scp

            try:
                with scp.SCPClient(handler._with_ssh.get_transport()) as scp:
                    scp.put(sys.argv[0], "/tmp/maio.py", preserve_times=True)
                handler._with_ssh.exec_command(
                    f"cd /tmp && python3 /tmp/maio.py -s 1 --log-level INFO -i {handler._self_addr} --remote-port={handler._bind_port}"
                )
            except scp.SCPException as e:
                LOG.error(f"File upload using SCP failed, reason={e}")
        except ImportError:
            LOG.error(f"The scp module is not installed, skipping remote execution")
    ########

    while True:
        if handler._terminated:
            break
        client_sock, _ = handler._sock.accept()
        LOG.info(
            f"Connected to the monitor daemon, forward={client_sock.getpeername()} -> {client_sock.getsockname()}"
        )
        thread_obj = threading.Thread(
            target=maio_intl_delegate_th, args=(handler, client_sock, args.listpath)
        )
        thread_obj.daemon = True
        thread_obj.start()
        handler._peer_jobs.append(thread_obj)


def maio_intl_run_sensor(handler: MAIORemoteHandler, args):
    """ """
    LOG.info(
        f"Created new thread for client, tid={threading.get_ident()}, connecting to {handler._monitor_addr}:{handler._bind_port}"
    )
    try:
        handler._sock.connect((handler._monitor_addr, handler._bind_port))
        LOG.info("Connected.")
        while True:
            if handler._terminated:
                break

            data = handler._sock.recv(65535)
            while True:
                if data[-4:] == b"\x00\x00\x00\x00":
                    break
                # maybe it is truncated
                _data = handler._sock.recv(65535)
                data = data + _data
            if len(data) == 0:
                LOG.warning(
                    f"monitor was disconnected, target={handler._sock.getpeername()}"
                )
                break

            if not maio_intl_msg_dissect(handler, None, data):
                handler.try_terminate()

    except ConnectionRefusedError:
        LOG.error(f"Please check the monitoring device, maybe it is not binded address")
        handler.try_terminate()
    except ConnectionResetError:
        LOG.warning(f"The connection was reset by monitor, terminating process")
        handler.try_terminate()


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
        username = args.user
        password = args.password
        _pw_masked = "*" * len(password)
        LOG.info(
            f"Connecting to -> {username}@{remote_ip}:{remote_port}, PASS={_pw_masked}"
        )
        try:
            import paramiko

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=remote_ip,
                port=remote_port,
                username=username,
                password=password,
            )
            LOG.info("Connected SSH.")
        except ImportError as e:
            LOG.error(
                f"paramiko is not installed, skipping a process for delegate with SSH"
            )
        except paramiko.AuthenticationException as e:
            LOG.error(f"SSH connection was failed, reason={e}")
            sys.exit(1)
    ###########
    return MAIORemoteHandler(
        MAIO_SYSTEM_TYPE_MONITOR, with_mont_addr=None, with_ssh=ssh, with_args=args
    )


def main_with_sensor(args) -> MAIORemoteHandler:
    monitor_ip = args.ip
    if monitor_ip is None:
        LOG.error(
            "You need to input the monitor ip address when system type is sensor (usuge ip flag)!"
        )
        return None
    return MAIORemoteHandler(
        MAIO_SYSTEM_TYPE_SENSOR, with_mont_addr=monitor_ip, with_args=args
    )


def main_wtih_arguments(args, system_type: int):
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
            rslt: MAIOMessage = maio_proc_handler.poll()
            if rslt == None:
                time.sleep(0.01)
            else:
                LOG.debug(
                    f"Ingress MAIO Message, type={maio_msg_print_message(rslt.type)}"
                )

                if system_type == MAIO_SYSTEM_TYPE_MONITOR:
                    ################################################
                    ######## Monitor Only

                    if rslt.type == MAIO_MSG_REQUEST_PROCESS:
                        raise Exception("Can't reach this function in Monitor")

                    elif rslt.type == MAIO_MSG_RECORD_PROCESS_REPORTED:
                        maio_intl_create_proc_record(
                            maio_proc_handler,
                            rslt,
                            MAIO_SYSTEM_TYPE_MONITOR,
                            args.delay,
                        )

                    elif rslt.type == MAIO_MSG_RECORD_PROCESS_CAPTURED:
                        pid = rslt.data["pid"]
                        is_detected_worker = False
                        for r_worker in maio_proc_handler._records:
                            if r_worker._pid == pid:
                                for e in rslt.data["result"]:
                                    r_worker.insert(e)
                                is_detected_worker = True
                                break
                        if not is_detected_worker:
                            LOG.error(
                                f"Unknown PID Recorder, maybe it is killed by unknown or unexpected, skiping data={result}"
                            )

                    elif rslt.type == MAIO_MSG_RECORD_PROCESS_TERMINATED:
                        raise Exception("Can't reach this function in Monitor")

                    ################################################

                else:
                    ################################################
                    ######## Sensor Only

                    if rslt.type == MAIO_MSG_REQUEST_PROCESS:
                        LOG.info(
                            f"Process record is now started, pids={rslt.data.keys()}"
                        )
                        # ready for recording each process
                        msg = MAIOMessage._maio_msg_send_report_process(rslt.data)
                        maio_intl_create_proc_record(
                            maio_proc_handler, rslt, MAIO_SYSTEM_TYPE_SENSOR, args.delay
                        )
                        maio_proc_handler._sock.send(msg.to_packet_string())

                    elif rslt.type == MAIO_MSG_RECORD_PROCESS_CAPTURED:
                        pid = rslt.data["pid"]
                        is_detected_worker = False
                        for r_worker in maio_proc_handler._records:
                            if r_worker._pid == pid:
                                result = r_worker.poll()
                                LOG.debug(f"PID resource result is delegated, {result}")
                                data = {"pid": pid, "result": result}
                                maio_proc_handler._sock.send(
                                    MAIOMessage._maio_msg_send_capture_process_by_sensor(
                                        data
                                    ).to_packet_string()
                                )
                                is_detected_worker = True
                                break
                        if not is_detected_worker:
                            LOG.error(
                                f"Unknown PID Recorder, maybe it is killed by unknown or unexpected, skiping data={result}"
                            )

                    elif rslt.type == MAIO_MSG_RECORD_PROCESS_REPORTED:
                        raise Exception("Can't reach this function in Monitor")

                    elif rslt.type == MAIO_MSG_RECORD_PROCESS_TERMINATED:
                        raise Exception("Can't reach this function in Monitor")

                    ################################################

    else:
        LOG.error("MAIO Program handler was failed to execute job, terminated!")
        return 2


def maio_handle_logger(filename: str, logging_level: int) -> logging.Logger:
    """
    handle and initialize MAIO logging object
    """
    logger = logging.getLogger("maio-runtime")
    fomatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] [%(funcName)s:%(lineno)s] %(message)s"
    )
    fileHandler = logging.FileHandler(filename=filename)
    streamHandler = logging.StreamHandler()

    fileHandler.setFormatter(fomatter)
    streamHandler.setFormatter(fomatter)

    logger.addHandler(fileHandler)
    logger.addHandler(streamHandler)

    logger.setLevel(logging_level)
    return logger


if __name__ == "__main__":
    """
    Initialize program and dissect arguments, pass to main function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--user", metavar="username", help="SSH username")
    parser.add_argument("-p", "--password", metavar="password", help="SSH password")
    parser.add_argument(
        "--remote-port",
        metavar="remote_port",
        help="Set your remote port when sensor is connecting",
        type=int,
        default=MAIO_REMOTE_PORT,
    )
    parser.add_argument(
        "-i",
        "--ip",
        metavar="IP:[port]",
        help="Remote or client IP (e.x., 192.168.2.4, 192. 168.4.110:2004, ...)",
    )
    parser.add_argument("--log-level", help="Set logging level", default="INFO")
    parser.add_argument(
        "-d", "--delay", help="Set delay for monitoring resource", type=int, default=1
    )
    parser.add_argument(
        "-s",
        "--system-type",
        help="Set sensor mode (0=monitor, 1=sensor)",
        type=int,
        default=0,
    )
    args, another_args = parser.parse_known_args()

    if len(another_args) > 0:
        args.listpath = another_args[0]

    if not hasattr(args, "listpath"):
        args.listpath = "process.txt"

    log_level = logging._nameToLevel.get(args.log_level, logging.INFO)
    LOG = maio_handle_logger("./maio.log", log_level)

    LOG.info(
        f"@@@@@@ MAIO started, log_level={logging.getLevelName(log_level)}, system_type={args.system_type}"
    )
    LOG.debug(f"Given arguments: {args}")
    sys.exit(main_wtih_arguments(args, args.system_type))
