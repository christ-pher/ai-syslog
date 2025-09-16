#!/usr/bin/env python3

import socketserver
import socket
import re
import json
import datetime
import logging
import urllib.request
import urllib.parse
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class DeviceType(Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    CISCO = "cisco"
    UNKNOWN = "unknown"


@dataclass
class LogRecord:
    timestamp: str  # ISO format timestamp
    source_ip: str
    hostname: str
    device_type: str
    facility: str
    severity: str
    priority: int
    message: str
    raw_log: str
    cisco_facility: Optional[str] = None
    cisco_severity_num: Optional[str] = None
    cisco_mnemonic: Optional[str] = None
    windows_event_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for PocketBase storage."""
        data = asdict(self)
        # Remove None values to keep the record clean
        return {k: v for k, v in data.items() if v is not None}


class PocketBaseClient:
    def __init__(self, url: str = "http://0.0.0.0:8090"):
        self.url = url.rstrip('/')
        self.api_url = f"{self.url}/api"

    def create_record(self, collection: str, data: Dict[str, Any]) -> bool:
        """Create a record in PocketBase collection."""
        try:
            json_data = json.dumps(data).encode('utf-8')
            req = urllib.request.Request(
                f"{self.api_url}/collections/{collection}/records",
                data=json_data,
                headers={'Content-Type': 'application/json'}
            )

            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status == 200
        except Exception as e:
            logging.error(f"Failed to create PocketBase record: {e}")
            return False


class SyslogParser:
    def __init__(self):
        # RFC3164 syslog pattern
        self.rfc3164_pattern = re.compile(
            r'^<(\d+)>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$'
        )

        # RFC5424 syslog pattern
        self.rfc5424_pattern = re.compile(
            r'^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$'
        )

        # Cisco patterns for LEM/EMBLEM
        self.cisco_lem_pattern = re.compile(
            r'^<(\d+)>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+):\s+%(\w+)-(\d+)-(\w+):\s+(.*)$'
        )

        # Windows Event Log pattern (when forwarded via syslog)
        self.windows_pattern = re.compile(
            r'^<(\d+)>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+MSWinEventLog\s+(\d+)\s+(.*)$'
        )

    def parse_priority(self, priority: int) -> tuple:
        """Parse syslog priority to get facility and severity."""
        facility = priority >> 3
        severity = priority & 0x07

        severity_names = {
            0: "Emergency", 1: "Alert", 2: "Critical", 3: "Error",
            4: "Warning", 5: "Notice", 6: "Informational", 7: "Debug"
        }

        facility_names = {
            0: "kernel", 1: "user", 2: "mail", 3: "daemon", 4: "security",
            5: "syslogd", 6: "line printer", 7: "network news", 8: "uucp",
            9: "clock", 10: "security", 11: "ftp", 12: "ntp", 13: "log audit",
            14: "log alert", 15: "clock", 16: "local0", 17: "local1",
            18: "local2", 19: "local3", 20: "local4", 21: "local5",
            22: "local6", 23: "local7"
        }

        return facility_names.get(facility, f"facility_{facility}"), severity_names.get(severity, f"severity_{severity}")

    def detect_device_type(self, message: str, hostname: str) -> DeviceType:
        """Detect the type of device based on log content."""
        if "MSWinEventLog" in message or "EventLog" in message:
            return DeviceType.WINDOWS
        elif re.search(r'%\w+-\d+-\w+:', message):  # Cisco format
            return DeviceType.CISCO
        elif any(keyword in message.lower() for keyword in ['kernel:', 'systemd', 'sudo:', 'sshd[', 'sshd:', 'ssh:', 'cron:', 'postfix']):
            return DeviceType.LINUX
        else:
            return DeviceType.UNKNOWN

    def parse_cisco_log(self, match, source_ip: str) -> LogRecord:
        """Parse Cisco-specific log format (LEM/EMBLEM)."""
        priority_str, timestamp_str, hostname, facility, severity_num, mnemonic, message = match.groups()
        priority = int(priority_str)
        facility_name, severity_name = self.parse_priority(priority)

        try:
            timestamp = datetime.datetime.strptime(f"{datetime.datetime.now().year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            timestamp = datetime.datetime.now()

        return LogRecord(
            timestamp=timestamp.isoformat(),
            source_ip=source_ip,
            hostname=hostname,
            device_type=DeviceType.CISCO.value,
            facility=facility_name,
            severity=severity_name,
            priority=priority,
            message=message,
            raw_log=match.string,
            cisco_facility=facility,
            cisco_severity_num=severity_num,
            cisco_mnemonic=mnemonic
        )

    def parse_windows_log(self, match, source_ip: str) -> LogRecord:
        """Parse Windows-specific log format."""
        priority_str, timestamp_str, hostname, event_id, message = match.groups()
        priority = int(priority_str)
        facility_name, severity_name = self.parse_priority(priority)

        try:
            timestamp = datetime.datetime.strptime(f"{datetime.datetime.now().year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            timestamp = datetime.datetime.now()

        return LogRecord(
            timestamp=timestamp.isoformat(),
            source_ip=source_ip,
            hostname=hostname,
            device_type=DeviceType.WINDOWS.value,
            facility=facility_name,
            severity=severity_name,
            priority=priority,
            message=message,
            raw_log=match.string,
            windows_event_id=event_id
        )

    def parse_standard_log(self, match, device_type: DeviceType, source_ip: str) -> LogRecord:
        """Parse standard RFC3164 log format."""
        priority_str, timestamp_str, hostname, message = match.groups()
        priority = int(priority_str)
        facility_name, severity_name = self.parse_priority(priority)

        try:
            timestamp = datetime.datetime.strptime(f"{datetime.datetime.now().year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            timestamp = datetime.datetime.now()

        return LogRecord(
            timestamp=timestamp.isoformat(),
            source_ip=source_ip,
            hostname=hostname,
            device_type=device_type.value,
            facility=facility_name,
            severity=severity_name,
            priority=priority,
            message=message,
            raw_log=match.string
        )

    def parse(self, raw_message: str, source_ip: str) -> LogRecord:
        """Parse a raw syslog message."""
        raw_message = raw_message.strip()

        # Try Cisco LEM/EMBLEM format first
        cisco_match = self.cisco_lem_pattern.match(raw_message)
        if cisco_match:
            return self.parse_cisco_log(cisco_match, source_ip)

        # Try Windows format
        windows_match = self.windows_pattern.match(raw_message)
        if windows_match:
            return self.parse_windows_log(windows_match, source_ip)

        # Try standard RFC3164 format
        standard_match = self.rfc3164_pattern.match(raw_message)
        if standard_match:
            device_type = self.detect_device_type(raw_message, standard_match.group(3))
            return self.parse_standard_log(standard_match, device_type, source_ip)

        # Fallback for unmatched logs
        return LogRecord(
            timestamp=datetime.datetime.now().isoformat(),
            source_ip=source_ip,
            hostname="unknown",
            device_type=DeviceType.UNKNOWN.value,
            facility="Unknown",
            severity="Unknown",
            priority=0,
            message=raw_message,
            raw_log=raw_message
        )


class SyslogHandler(socketserver.BaseRequestHandler):
    def __init__(self, *args, **kwargs):
        self.parser = SyslogParser()
        self.pocketbase = PocketBaseClient()
        super().__init__(*args, **kwargs)

    def handle(self):
        data = self.request[0].decode('utf-8', errors='replace')
        socket_info = self.request[1]
        source_ip = self.client_address[0]

        log_record = self.parser.parse(data, source_ip)
        self.store_log(log_record)

    def store_log(self, log_record: LogRecord):
        """Store the parsed log record in PocketBase."""
        try:
            success = self.pocketbase.create_record("logs", log_record.to_dict())
            if not success:
                logging.warning(f"Failed to store log from {log_record.source_ip}")
        except Exception as e:
            logging.error(f"Error storing log: {e}")


class SyslogServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 514):
        self.host = host
        self.port = port
        self.server = None

    def start(self):
        """Start the syslog server."""
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

        logging.info(f"Starting syslog server on {self.host}:{self.port}")
        logging.info("Listening for logs from Windows Servers, Linux Servers, and Cisco devices...")
        logging.info("Logs will be stored in PocketBase at http://0.0.0.0:8090")
        logging.info("Press Ctrl+C to stop the server")

        try:
            self.server = socketserver.UDPServer((self.host, self.port), SyslogHandler)
            self.server.serve_forever()
        except KeyboardInterrupt:
            logging.info("Shutting down syslog server...")
        except PermissionError:
            logging.error(f"Permission denied: Cannot bind to port {self.port}")
            logging.error("Try running with sudo or use a port > 1024")
        except Exception as e:
            logging.error(f"Error starting server: {e}")
        finally:
            if self.server:
                self.server.shutdown()
                self.server.server_close()

    def stop(self):
        """Stop the syslog server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Python Syslog Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=514, help="Port to bind to (default: 514)")

    args = parser.parse_args()

    server = SyslogServer(args.host, args.port)
    server.start()
