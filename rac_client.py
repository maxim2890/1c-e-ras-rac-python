#!/usr/bin/env python3
"""Experimental native-free agent/worker administration client.

The plaintext profile is version-adaptive across observed 8.3.22, 8.3.23,
8.3.25 and early 8.3.27 servers. No persistent modifications are supported.
"""
import argparse
import datetime
from dataclasses import dataclass
import getpass
import json
import os
import re
import secrets
import socket
import sys
import time
import uuid

MARKER = bytes.fromhex('53f5c61a7b')
END = bytes.fromhex('6653b2a6')
ROOT = 'e23134a2-14ff-4160-ba5f-ccef04e3786f'
CREATOR = '7f58f27d-5ad8-43a1-aa1e-c982f41bed5c'
INTERFACE = '73cdaa77-2afc-436c-b738-58c772e3a0bf'
OBJECT_TAG = '3ace6d91-51bb-4344-9388-c8105ad4ad11'
CLUSTERS_TAG = '41344e9c-168a-4c10-8df4-0a3700dbd815'
INFOBASES_TAG = '59654aab-c9d2-49e0-ab3b-32f2a3595c5b'
SESSIONS_TAG = 'a3b238cc-3fa5-406b-a1eb-5347bcae06e2'
UUID_TAG = 'ae135932-4f94-44df-92c1-c91f15a92848'
BASELINE_VERSION = '8.3.22.2143'
KNOWN_PROTECTED_VERSIONS = frozenset(('8.3.27.2342',))


@dataclass(frozen=True)
class NativeProfile:
    """A selected native transport family and its wire identity."""

    family: str
    platform_version: str
    minimum_methods: int = 80

    @property
    def name(self):
        return self.family + '-' + self.platform_version


def plaintext_profile(platform_version):
    return NativeProfile('plaintext', platform_version)


def parse_values(text):
    """Bounded brace/quoted-string parser; unknown atom semantics stay opaque."""
    if len(text) > 1048576:
        raise ValueError('Text record too large')
    position = 0
    def value(depth=0):
        nonlocal position
        if depth > 64:
            raise ValueError('Record nesting limit exceeded')
        while position < len(text) and text[position].isspace(): position += 1
        if position == len(text): raise ValueError('Missing value')
        if text[position] == '{':
            position += 1
            items = []
            while True:
                while position < len(text) and text[position].isspace(): position += 1
                if position == len(text): raise ValueError('Unclosed brace')
                if text[position] == '}':
                    position += 1
                    return items
                if items:
                    if text[position] != ',': raise ValueError('Expected comma')
                    position += 1
                items.append(value(depth + 1))
        if text[position] == '"':
            position += 1
            result = ''
            while position < len(text):
                ch = text[position]; position += 1
                if ch == '"':
                    if position < len(text) and text[position] == '"':
                        result += '"'; position += 1
                    else: return result
                else: result += ch
            raise ValueError('Unclosed string')
        start = position
        while position < len(text) and text[position] not in ',{}': position += 1
        atom = text[start:position].strip()
        if not atom: raise ValueError('Empty atom')
        try: return int(atom)
        except ValueError: return atom
    result = [value()]
    while position < len(text):
        if text[position].isspace(): position += 1; continue
        if text[position] != ',': raise ValueError('Trailing record data')
        position += 1
        result.append(value())
    return result


def tagged(tree, tag):
    if isinstance(tree, list):
        if len(tree) >= 3 and tree[0] in ('#', 35) and tree[1] == tag: return tree[2]
        for child in tree:
            result = tagged(child, tag)
            if result is not None: return result
    return None


def parse_binary_values(data):
    """Decode the bounded native list scalar subset established by static codec.

    Empty strings/null UUIDs share the integer-zero token; callers apply their
    known schema rather than guessing scalar types globally.
    """
    position = 0
    roots, stack = [], []
    nodes = 0
    def take(size):
        nonlocal position
        if size < 0 or size > 1048576: raise ValueError('Binary scalar exceeds limit')
        if position + size > len(data): raise ValueError('Truncated binary scalar')
        result = data[position:position + size]; position += size
        return result
    def number(size): return int.from_bytes(take(size), 'little')
    def append(value):
        nonlocal nodes
        nodes += 1
        if nodes > 65536: raise ValueError('Binary node limit exceeded')
        (stack[-1] if stack else roots).append(value)
    while position < len(data):
        token = number(1)
        if token & 0x20:
            if not stack: raise ValueError('Unmatched binary close')
            stack.pop()
        if token & 0x40:
            if len(stack) >= 64: raise ValueError('Binary nesting limit exceeded')
            value = []; append(value); stack.append(value)
        kind = token & 0x1f
        if kind == 0: continue
        if 1 <= kind <= 10: value = kind - 1
        elif kind in (11, 13, 15, 17):
            value = number({11: 1, 13: 2, 15: 4, 17: 8}[kind])
        elif kind == 21: value = str(uuid.UUID(bytes_le=take(16)))
        elif kind in (23, 24, 25, 26, 27, 28):
            units = number({23: 1, 24: 2, 25: 8, 26: 1, 27: 2, 28: 8}[kind])
            wide = kind <= 25
            value = take(units * (2 if wide else 1)).decode('utf-16-le' if wide else 'latin-1')
        else: raise ValueError('Unsupported native binary scalar kind ' + str(kind))
        append(value)
    if stack: raise ValueError('Unclosed binary list')
    if not roots: raise ValueError('Empty binary record')
    return roots


def encode_binary_values(values):
    """Encode only the scalar/list subset used by the observed read requests."""
    def scalar(value, flags):
        if isinstance(value, list):
            if not value: return bytes([flags | 0x40, 0x20])
            return scalar(value[0], flags | 0x40) + b''.join(scalar(v, 0x80) for v in value[1:]) + b'\x20'
        if type(value) is int:
            if not 0 <= value <= 0xffffffffffffffff: raise ValueError('Unsupported native integer')
            if value <= 9: return bytes([flags | (value + 1)])
            size, kind = next((size, kind) for size, kind in ((1,11),(2,13),(4,15),(8,17)) if value < 1 << (8 * size))
            return bytes([flags | kind]) + value.to_bytes(size, 'little')
        if isinstance(value, uuid.UUID): return bytes([flags | 21]) + value.bytes_le
        if isinstance(value, str):
            if not value: return scalar(0, flags)
            if len(value) == 1 and ord(value) <= 255: return scalar(ord(value), flags)
            try: payload = value.encode('latin-1'); units = len(payload); base = 26
            except UnicodeEncodeError:
                payload = value.encode('utf-16-le'); units = len(payload) // 2; base = 23
            size, extra = (1, 0) if units <= 255 else ((2, 1) if units <= 65535 else (8, 2))
            if len(payload) > 1048576: raise ValueError('Binary string exceeds limit')
            return bytes([flags | (base + extra)]) + units.to_bytes(size, 'little') + payload
        raise ValueError('Unsupported native request value')
    return b''.join(scalar(v, 0 if i == 0 else 0x80) for i, v in enumerate(values))


def native_string(value):
    if isinstance(value, str): return value
    if type(value) is int and 0 <= value <= 255:
        return '' if value == 0 else chr(value)
    raise ValueError('Unexpected native string scalar')


def native_text_string(value):
    if not isinstance(value, str) or len(value.encode('utf-8')) > 65535:
        raise ValueError('Invalid native authentication string')
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError('Control character in native authentication string')
    return '{"S","' + value.replace('"', '""') + '"}'


class RemoteError(ValueError):
    """A native exception reply; never interpret it as a successful result."""


class UnsupportedNativeSecurity(ValueError):
    """The agent requires a newer protected bootstrap not yet implemented."""


class NativeVersionMismatch(ValueError):
    """The plaintext profile is valid but its declared platform version differs."""

    def __init__(self, client_version, server_version, message):
        super().__init__(message)
        self.client_version = client_version
        self.server_version = server_version


def check_remote_error(reply):
    if (isinstance(reply, list) and reply and isinstance(reply[0], list)
            and reply[0] and reply[0][0] == 2):
        messages = []
        def walk(node):
            if isinstance(node, list):
                if (len(node) >= 2 and isinstance(node[0], str)
                        and isinstance(node[1], str)):
                    try: uuid.UUID(node[0])
                    except ValueError: pass
                    else: messages.append(node[1][:1000])
                for child in node: walk(child)
        walk(reply[0])
        message = '; '.join(messages) or 'native exception'
        if 'Different client and server versions' in message:
            match = re.search(r'\(([0-9]+(?:\.[0-9]+){3})\s*-\s*([0-9]+(?:\.[0-9]+){3})\)', message)
            if match:
                raise NativeVersionMismatch(match.group(1), match.group(2), message)
        raise RemoteError('Agent rejected request: ' + message)


class Channel:
    def __init__(self, connection, timeout):
        self.connection, self.timeout, self.buffer = connection, timeout, bytearray()

    def receive(self, greeting=False):
        deadline = time.monotonic() + self.timeout
        while True:
            if greeting and len(self.buffer) >= 5:
                data = bytes(self.buffer[:5]); del self.buffer[:5]
                if data != MARKER: raise ValueError('Unexpected server greeting: ' + data.hex())
                return data
            if not greeting:
                # Native activity records may occur between application records.
                while self.buffer.startswith(bytes.fromhex('214754b3')):
                    del self.buffer[:4]
                end = self.buffer.find(END)
                while end >= 0:
                    data = bytes(self.buffer[:end])
                    # A standalone delimiter carries no application values.
                    if not data:
                        del self.buffer[:len(END)]
                        end = self.buffer.find(END)
                        continue
                    if data.startswith(b'\xef\xbb\xbf'):
                        reply = parse_values(data[3:].decode('utf-8'))
                    else:
                        try:
                            reply = parse_binary_values(data)
                        except ValueError as exc:
                            # The delimiter bytes may occur inside a GUID/string.
                            # Only a complete bounded binary record terminates here.
                            if str(exc).startswith(('Truncated binary', 'Unclosed binary')):
                                end = self.buffer.find(END, end + 1)
                                continue
                            raise ValueError('Native binary decode failed: ' + str(exc)
                                             + '; frame_bytes=' + str(len(data))
                                             + '; prefix_hex=' + data[:256].hex()) from exc
                    del self.buffer[:end + len(END)]
                    check_remote_error(reply)
                    return reply
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise TimeoutError('Native reply timed out')
            self.connection.settimeout(remaining)
            block = self.connection.recv(4096)
            if not block: raise ConnectionError('Agent closed the connection')
            self.buffer.extend(block)
            if len(self.buffer) > 1048576: raise ValueError('Native reply exceeds 1 MiB limit')

    def request(self, text, stage='native request'):
        try:
            self.connection.sendall(b'\xef\xbb\xbf' + text.encode('utf-8') + END)
            return self.receive()
        except (RemoteError, NativeVersionMismatch, UnsupportedNativeSecurity):
            raise
        except (OSError, ValueError) as exc:
            raise ValueError(stage + ': ' + str(exc)) from exc

    def request_binary(self, values, stage):
        try:
            self.connection.sendall(encode_binary_values(values) + END)
            return self.receive()
        except (RemoteError, NativeVersionMismatch, UnsupportedNativeSecurity):
            raise
        except (OSError, ValueError) as exc:
            raise ValueError(stage + ': ' + str(exc)) from exc

def creation_request(counter, platform_version=BASELINE_VERSION,
                     class_id='bc9113bc-5b88-4c9f-9fc0-ff7ade5450f0'):
    # Fixed identifiers and argument order come from the supplied successful trace.
    if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}', platform_version):
        raise ValueError('Invalid native platform version')
    hostname = socket.gethostname().replace('"', '""')
    initial = ('{0,' + ROOT + ',' + str(counter) + ',4,' + CREATOR + ',0,1,11,0,\r\n'
               '{"S","##AdminProcess##:##AdminProcess##"},0,\r\n'
               '{"#",ae135932-4f94-44df-92c1-c91f15a92848,\r\n'
               '{1,' + class_id + '}\r\n},0,\r\n'
               '{"S","RAS"},0,\r\n{"S","' + hostname + '"},2,\r\n'
               '{"#",671507fd-50a9-4b63-b70e-58b3d364f48f,\r\n{}\r\n},1,0,\r\n'
               '{"S","' + platform_version + '"},0,\r\n{"S","1en_US_POSIX"},0,\r\n'
               '{"S","1en_US_POSIX"},0,\r\n'
               '{"#",ae135932-4f94-44df-92c1-c91f15a92848,\r\n'
               '{1,00000000-0000-0000-0000-000000000000}\r\n},1}')
    return initial


WORKER_INTERFACE = '7607aa1f-f87e-47a2-8a6b-701c7105ca63'
WORKER_CLASS = 'a2c6af52-7d8b-46ef-9a69-cb1fa650e4f5'
SETTINGS_TAG = '47ac43bf-50ac-4062-b273-2026c08159b1'


def read_value(reply, argument_count, stage):
    if (not isinstance(reply, list) or len(reply) != 2 or reply[1] != 2
            or not isinstance(reply[0], list) or len(reply[0]) != 6 + argument_count
            or reply[0][0] != 1 or type(reply[0][1]) is not int or reply[0][2] != 1
            or reply[0][4:] != [argument_count] + [0] * argument_count + [0]):
        raise ValueError('Unexpected ' + stage + ' reply envelope')
    return reply[0][3]


def parse_connection_parameters(text):
    """Read 1C key=value syntax for selective or explicit sensitive output."""
    result = {}; position = 0
    while position < len(text):
        while position < len(text) and text[position] in '; \r\n': position += 1
        if position == len(text): break
        end = text.find('=', position)
        if end < 0: raise ValueError('Malformed database connection parameters')
        key = text[position:end].strip(); position = end + 1
        value = ''; quoted = False
        while position < len(text):
            ch = text[position]; position += 1
            if ch == '"':
                if quoted and position < len(text) and text[position] == '"':
                    value += '"'; position += 1
                else: quoted = not quoted
            elif ch == ';' and not quoted: break
            else: value += ch
        if quoted: raise ValueError('Unclosed database parameter quote')
        result[key.casefold()] = value
    return result


def native_int32(value):
    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
        raise ValueError('Invalid native integer setting')
    return value


def native_bool(value):
    if type(value) not in (bool, int) or value not in (0, 1):
        raise ValueError('Invalid native Boolean setting')
    return bool(value)


def native_date(value):
    # Live nonzero 8.3.22 fixtures corroborate the older core::Date layout.
    # Server-local calendar values; zero is the unset representation.
    if type(value) is not int or not 0 <= value <= 3155378975999999:
        raise ValueError('Invalid native date setting')
    if value == 0: return None
    return (datetime.datetime(1, 1, 1) + datetime.timedelta(microseconds=value * 100)).isoformat()


def native_uuid_or_zero(value):
    """Decode a native UUID slot whose absent representation is integer zero."""
    if value == 0:
        return str(uuid.UUID(int=0))
    return str(uuid.UUID(value))


def native_pid(value):
    if isinstance(value, str):
        return native_string(value)
    if type(value) is int and 0 <= value < (1 << 32):
        return str(value)
    raise ValueError('Unexpected native process identifier')


def decode_sessions(reply, expected_infobase):
    """Decode the observed 8.3.22 getSeances result without naming unknown fields."""
    if (not isinstance(reply, list) or len(reply) != 2 or reply[1] != 2
            or not isinstance(reply[0], list) or len(reply[0]) != 9
            or reply[0][0] != 1 or type(reply[0][1]) is not int
            or reply[0][2:7] != [3, 3, 0, 0, 1] or reply[0][8] != 0):
        raise ValueError('Unexpected session-list reply envelope')
    rows = tagged(reply[0][7], SESSIONS_TAG)
    if (not isinstance(rows, list) or not rows or type(rows[0]) is not int
            or rows[0] != len(rows) - 1):
        raise ValueError('Unexpected session-list typed result')
    result = []
    for wrapped in rows[1:]:
        # The native server appends a fourth element when it has per-session
        # license diagnostics.  The session record itself keeps the same
        # 53-field layout.  Validate and ignore that diagnostic envelope: it
        # may contain verbose local licensing errors and is not user data.
        no_diagnostics = (isinstance(wrapped, list) and len(wrapped) == 3
                          and wrapped[2] == 0)
        with_diagnostics = (isinstance(wrapped, list) and len(wrapped) == 4
                            and type(wrapped[2]) is int and 0 < wrapped[2] <= 64
                            and isinstance(wrapped[3], list)
                            and len(wrapped[3]) == wrapped[2] + 1)
        if (not (no_diagnostics or with_diagnostics) or wrapped[0] != 1
                or not isinstance(wrapped[1], list) or len(wrapped[1]) != 53):
            raise ValueError('Unsupported native session record')
        row = wrapped[1]
        session_id = str(uuid.UUID(row[0]))
        infobase_id = str(uuid.UUID(row[1]))
        if infobase_id != expected_infobase:
            raise ValueError('Session belongs to a different infobase')
        # These identity and lifecycle positions are corroborated by the same
        # live exchange decoded through the public RAS SessionInfo schema.
        service_layout = isinstance(row[9], str)
        item = {
            'session': session_id,
            'infobase': infobase_id,
            'infobase-name': native_string(row[2]),
            'infobase-descr': native_string(row[3]),
            'session-number': native_int32(row[4]),
            'started-at': native_date(row[5]),
            'last-active-at': native_date(row[6]),
            'host': native_string(row[7]),
            'user-name': native_string(row[8]),
            'working-process-host': native_string(row[9] if service_layout else row[45]),
            'working-process-port': native_int32(row[10] if service_layout else row[46]),
            'working-process-pid': native_pid(row[11] if service_layout else row[47]),
            'app-id': native_string(row[12]),
            'connection': native_uuid_or_zero(row[13]),
            'process': native_uuid_or_zero(row[15] if service_layout else row[19]),
            'locale': native_string(row[17]),
            'client-version': native_string(row[26]),
            'passive-session-hibernate-time': native_int32(row[40]),
            'hibernate-session-terminate-time': native_int32(row[41]),
        }
        if service_layout:
            item.update({
                'blocked-by-dbms': native_int32(row[19]),
                'blocked-by-ls': native_int32(row[20]),
                'calls-all': native_int32(row[21]),
            })
        result.append(item)
    return result


def decode_settings(reply, expected_id, include_sensitive=False):
    record = tagged(read_value(reply, 1, 'worker settings'), SETTINGS_TAG)
    if not isinstance(record, list) or len(record) != 19:
        raise ValueError('Unsupported full infobase settings record')
    if str(uuid.UUID(record[1])) != expected_id:
        raise ValueError('Worker returned a different infobase')
    restrictions = record[10]
    if not isinstance(restrictions, list) or len(restrictions) != 7:
        raise ValueError('Unsupported session restriction settings')
    params = parse_connection_parameters(native_string(record[8]))
    result = {'infobase': expected_id, 'name': native_string(record[0]),
              'descr': native_string(record[2]), 'dbms': native_string(record[3]),
              'db-server': native_string(record[4]), 'db-name': native_string(record[5]),
              'db-user': native_string(record[6]), 'date-offset': native_int32(record[9])}
    for key, field in [('Locale', 'locale'), ('SLev', 'security-level'),
                       ('SchJobDn', 'scheduled-jobs-deny'), ('LicDstr', 'license-distribution')]:
        if key.casefold() not in params: continue
        value = params[key.casefold()]
        if field == 'security-level': value = native_int32(int(value))
        elif field == 'scheduled-jobs-deny':
            if value not in ('Y', 'N'): raise ValueError('Unknown scheduled jobs flag')
            value = value == 'Y'
        elif field == 'license-distribution':
            if value not in ('Y', 'N'): raise ValueError('Unknown license distribution flag')
            value = int(value == 'Y')
        result[field] = value
    result.update({'sessions-deny': native_bool(restrictions[0]),
                   'scheduled-jobs-deny': native_bool(record[11]),
                   'license-distribution': native_int32(record[12]),
                   'external-session-manager-required': native_bool(record[14]),
                   'reserve-working-processes': native_bool(record[18]),
                   'security-profile-name': native_string(record[15]),
                   'safe-mode-security-profile-name': native_string(record[16]),
                   'denied-from': native_date(restrictions[1]),
                   'denied-to': native_date(restrictions[2]),
                   'denied-message': native_string(restrictions[3])})
    if include_sensitive:
        # Preserve exact native values. The server may return a mask/sentinel
        # instead of a recoverable password; do not reinterpret that value.
        result['native-db-password-field'] = native_string(record[7])
        if result['native-db-password-field'] == '\ufffd':
            result['native-db-password-field-state'] = 'redacted-preserve-existing-sentinel'
        result['database-connection-string'] = native_string(record[8])
        result['connection-parameters'] = params
        result['unmapped-native-fields'] = {
            '10.4': restrictions[4], '10.5': restrictions[5],
            '10.6': restrictions[6], '13': record[13], '17': record[17]}
    return result


def worker_settings(address, infobase_id, timeout, host_override=None,
                    cluster_user='', cluster_password='', include_sensitive=False):
    try:
        advertised_host, port_text = address.rsplit(':', 1)
        advertised_host = advertised_host.strip('[]'); port = int(port_text)
    except (AttributeError, ValueError): raise ValueError('Invalid server-directed worker address')
    if not advertised_host or not 1 <= port <= 65535:
        raise ValueError('Invalid worker host/port')
    host = host_override or advertised_host
    counter = secrets.randbelow(1000000000) + 1
    try:
        with socket.create_connection((host, port), timeout) as connection:
            channel = Channel(connection, timeout); channel.receive(greeting=True)
            creation = channel.request(creation_request(counter, class_id=WORKER_CLASS),
                                       stage='worker creation')
            if (not isinstance(creation, list) or len(creation) != 2 or creation[1] != 0
                    or not isinstance(creation[0], list) or len(creation[0]) < 4
                    or creation[0][0] != 1 or creation[0][2] != 1):
                raise ValueError('Unexpected worker creation reply')
            reference = tagged(creation[0][3], OBJECT_TAG)
            if not isinstance(reference, list) or len(reference) != 1:
                raise ValueError('Missing worker remote-object reference')
            object_id = str(uuid.UUID(reference[0])); prefix = '{0,' + object_id + ','
            capability = channel.request(prefix + str(counter + 1) + ',1,' + WORKER_INTERFACE + '}', stage='worker interface')
            if (len(capability) != 1 or not isinstance(capability[0], list)
                    or len(capability[0]) != 3 or capability[0][0] != 1 or capability[0][2] != 16):
                raise ValueError('Observed 16-method worker interface required')
            for offset, method in ((2, 11), (3, 0)):
                user, password = ((cluster_user, cluster_password) if method == 11 else ('', ''))
                auth = (prefix + str(counter + offset) + ',4,' + WORKER_INTERFACE + ','
                        + str(method) + ',3,2,0,' + native_text_string(user) + ',0,'
                        + native_text_string(password) + '}')
                try:
                    reply = channel.request(auth, stage='worker authentication ' + str(method))
                except (OSError, ValueError) as exc:
                    raise ValueError('worker authentication ' + str(method) + ' failed ('
                                     + type(exc).__name__ + ')') from None
                if (len(reply) != 2 or reply[1] != 2 or not isinstance(reply[0], list)
                        or len(reply[0]) != 7 or reply[0][0] != 1
                        or reply[0][2:] != [3, 2, 0, 0, 0]):
                    raise ValueError('Unexpected worker authentication reply')
            reply = channel.request_binary([[0, uuid.UUID(object_id), counter + 4, 4,
                uuid.UUID(WORKER_INTERFACE), 2, 1, 1, 0,
                ['#', uuid.UUID(UUID_TAG), [1, uuid.UUID(infobase_id)]]]], stage='worker settings read')
            return decode_settings(reply, infobase_id, include_sensitive)
    except (OSError, ValueError) as exc:
        # Do not include raw worker bytes, which may contain connection secrets.
        message = str(exc).split('; frame_bytes=')[0]
        raise ValueError('Worker ' + host + ':' + str(port) + ': ' + message) from None


def _list_clusters_profile(host, port=1540, timeout=10, infobases=False, details=False, sessions=False, worker_host=None,
                           cluster_filter=None, infobase_filter=None, cluster_user='', cluster_password='',
                           include_sensitive=False, platform_version='8.3.22.2143'):
    if not isinstance(cluster_user, str) or not isinstance(cluster_password, str):
        raise ValueError('Cluster credentials must be text')
    cluster_filter = str(uuid.UUID(cluster_filter)) if cluster_filter else None
    infobase_filter = str(uuid.UUID(infobase_filter)) if infobase_filter else None
    infobases = infobases or details or sessions or bool(infobase_filter)
    counter = secrets.randbelow(1000000000) + 1
    initial = creation_request(counter, platform_version)
    with socket.create_connection((host, port), timeout) as connection:
        channel = Channel(connection, timeout)
        channel.receive(greeting=True)
        creation = channel.request(initial)
        if (not isinstance(creation, list) or len(creation) != 2 or creation[1] != 0
                or not isinstance(creation[0], list) or len(creation[0]) < 4
                or creation[0][0] != 1 or not isinstance(creation[0][1], int)
                or creation[0][2] != 1):
            raise ValueError('Unexpected creation reply envelope')
        reference = tagged(creation[0][3], OBJECT_TAG)
        if not isinstance(reference, list) or len(reference) != 1:
            raise ValueError('Agent did not return the observed remote-object reference')
        object_id = str(uuid.UUID(reference[0]))
        # Reproduce only the two observed read requests, using the returned object.
        prefix = '{0,' + object_id + ','
        capability = channel.request(prefix + str(counter + 1) + ',1,' + INTERFACE + '}')
        if (len(capability) != 1 or not isinstance(capability[0], list)
                or len(capability[0]) != 3 or capability[0][0] != 1
                or not isinstance(capability[0][1], int) or type(capability[0][2]) is not int
                or capability[0][2] < 80):
            raise ValueError('Unexpected interface reply; profile requires at least 80 methods: '
                             + repr(capability)[:500])
        reply = channel.request(prefix + str(counter + 2) + ',4,' + INTERFACE + ',0,1,0}')
        if (len(reply) != 2 or reply[1] != 2 or not isinstance(reply[0], list)
                or len(reply[0]) != 6 or reply[0][0] != 1
                or not isinstance(reply[0][1], int) or reply[0][2] != 1
                or reply[0][4:] != [0, 0]):
            raise ValueError('Unexpected cluster-list reply envelope')
        rows = tagged(reply[0][3], CLUSTERS_TAG)
        if not isinstance(rows, list) or not rows or not isinstance(rows[0], int):
            raise ValueError('Agent did not return the observed cluster-list type')
        if rows[0] != len(rows) - 1: raise ValueError('Cluster count does not match record')
        clusters = []
        for row in rows[1:]:
            if not isinstance(row, list) or len(row) < 3: raise ValueError('Malformed cluster row')
            clusters.append({'cluster': str(uuid.UUID(row[0])), 'name': row[1],
                             'native_fields': row[2:]})
        if cluster_filter:
            clusters = [cluster for cluster in clusters if cluster['cluster'] == cluster_filter]
            if not clusters: raise ValueError('Selected cluster was not returned by the agent')
        if infobases:
            for index, cluster in enumerate(clusters):
                cluster_id = str(uuid.UUID(cluster['cluster']))
                # Method 9 takes cluster UUID, administrator name and password.
                # The first invocation on this connection uses the observed
                # text envelope; subsequent invocations use binary records.
                try:
                    if index == 0:
                        auth = (prefix + str(counter + 3) + ',4,' + INTERFACE
                                + ',9,3,3,0,{"#",' + UUID_TAG + ',{1,' + cluster_id
                                + '}},0,' + native_text_string(cluster_user)
                                + ',0,' + native_text_string(cluster_password) + '}')
                        auth_reply = channel.request(auth, stage='cluster authentication')
                    else:
                        auth_reply = channel.request_binary([[0, uuid.UUID(object_id),
                            counter + 3 + index * 2, 4, uuid.UUID(INTERFACE), 9, 3, 3,
                            0, ['#', uuid.UUID(UUID_TAG), [1, uuid.UUID(cluster_id)]],
                            0, ['S', cluster_user], 0, ['S', cluster_password]]],
                            stage='cluster authentication')
                except (OSError, ValueError) as exc:
                    # Server exceptions may echo submitted credentials.
                    raise ValueError('Cluster authentication failed (' + type(exc).__name__ + ')') from None
                if (not isinstance(auth_reply, list) or len(auth_reply) != 2
                        or auth_reply[1] != 2 or not isinstance(auth_reply[0], list)
                        or len(auth_reply[0]) != 8 or auth_reply[0][0] != 1
                        or not isinstance(auth_reply[0][1], int)
                        or auth_reply[0][2:] != [3, 3, 0, 0, 0, 0]):
                    raise ValueError('Unexpected cluster-authentication reply')
                values = [[0, uuid.UUID(object_id), counter + 4 + index * 2, 4,
                           uuid.UUID(INTERFACE), 5, 1, 1, 0,
                           ['#', uuid.UUID(UUID_TAG), [1, uuid.UUID(cluster_id)]]]]
                reply = channel.request_binary(values, stage='infobase list')
                if (not isinstance(reply, list) or len(reply) != 2 or reply[1] != 2
                        or not isinstance(reply[0], list) or len(reply[0]) != 7
                        or reply[0][0] != 1 or not isinstance(reply[0][1], int)
                        or reply[0][2] != 1 or reply[0][4:] != [1, 0, 0]):
                    raise ValueError('Unexpected infobase-list reply envelope: ' + repr(reply)[:2000])
                rows = tagged(reply[0][3], INFOBASES_TAG)
                if (not isinstance(rows, list) or not rows or type(rows[0]) is not int
                        or rows[0] != len(rows) - 1):
                    raise ValueError('Unexpected infobase-list typed result: ' + repr(reply)[:2000])
                cluster['infobases'] = []
                for row in rows[1:]:
                    if not isinstance(row, list) or len(row) != 3:
                        raise ValueError('Unexpected infobase summary record')
                    cluster['infobases'].append({'infobase': str(uuid.UUID(row[0])),
                                                'name': native_string(row[1]), 'descr': native_string(row[2])})
        if infobase_filter:
            for cluster in clusters:
                cluster['infobases'] = [base for base in cluster['infobases'] if base['infobase'] == infobase_filter]
            if not any(cluster['infobases'] for cluster in clusters):
                raise ValueError('Selected infobase was not returned by the agent')
        if sessions:
            session_counter = counter + 20000
            for cluster in clusters:
                for base in cluster['infobases']:
                    session_counter += 1
                    request = [[0, uuid.UUID(object_id), session_counter, 0, 4,
                        uuid.UUID(INTERFACE), 31, 3, 3,
                        0, ['#', uuid.UUID(UUID_TAG), [1, uuid.UUID(cluster['cluster'])]],
                        0, ['#', uuid.UUID(UUID_TAG), [1, uuid.UUID(base['infobase'])]], 1]]
                    reply = channel.request_binary(request, stage='session list')
                    base['sessions'] = decode_sessions(reply, base['infobase'])
        if details:
            lookup_counter = counter + 10000
            for cluster in clusters:
                for base in cluster['infobases']:
                    lookup_counter += 1
                    # Captured serverProcessesForConnections query. The per-query UUID
                    # varies between native captures; it is not a fixed service ID.
                    request = [[0, uuid.UUID(object_id), lookup_counter, 0, 4,
                        uuid.UUID(INTERFACE), 76, 1, 3,
                        0, ['#', uuid.UUID(UUID_TAG), [1, uuid.UUID(cluster['cluster'])]],
                        0, ['S', base['name']],
                        0, ['#', uuid.UUID(UUID_TAG), [1, uuid.uuid4()]]]]
                    redirect = read_value(channel.request_binary(request, stage='worker lookup'), 3, 'worker lookup')
                    if (not isinstance(redirect, list) or len(redirect) != 2
                            or redirect[0] not in ('S', 83)):
                        raise ValueError('Expected server-directed worker address')
                    address = native_string(redirect[1])
                    base.update(worker_settings(address, base['infobase'], timeout, worker_host,
                                                cluster_user, cluster_password, include_sensitive))
        return {'endpoint': {'host': host, 'port': port},
                'experimental_profile': 'plaintext-' + platform_version,
                'clusters': clusters, 'capability_reply_raw': capability,
                'limitations': 'The plaintext profile is live validated on 8.3.22.2143 and cluster discovery is validated through 8.3.27.2214. Later protected-bootstrap profiles are not implemented. Session listing reports active sessions, not the infobase application user directory. Credential-bearing and unmapped native settings require --include-sensitive; a returned password field may be a server-provided mask rather than a recoverable password. Native session fields remain partly uninterpreted. Server-agent administrator authentication remains unsupported.'}


def list_clusters(host, port=1540, timeout=10, infobases=False, details=False, sessions=False, worker_host=None,
                  cluster_filter=None, infobase_filter=None, cluster_user='', cluster_password='',
                  include_sensitive=False, platform_version='auto'):
    """Select a versioned native profile, reconnecting once on a safe mismatch."""
    selected = BASELINE_VERSION if platform_version == 'auto' else platform_version
    options = dict(infobases=infobases, details=details, sessions=sessions,
                   worker_host=worker_host, cluster_filter=cluster_filter,
                   infobase_filter=infobase_filter, cluster_user=cluster_user,
                   cluster_password=cluster_password, include_sensitive=include_sensitive)
    try:
        return _list_clusters_profile(host, port, timeout, platform_version=selected, **options)
    except NativeVersionMismatch as exc:
        if platform_version != 'auto':
            raise
        try:
            return _list_clusters_profile(host, port, timeout,
                                          platform_version=exc.server_version, **options)
        except (ConnectionError, RemoteError, ValueError) as retry:
            if isinstance(retry, NativeVersionMismatch):
                raise
            raise UnsupportedNativeSecurity(
                'Agent version ' + exc.server_version + ' does not accept the observed '
                'plaintext profile after version discovery. It may require the protected '
                'public-key bootstrap; use ras_client.py through RAS.') from None


def _fingerprint_plaintext(host, port, timeout, platform_version):
    """Negotiate object creation and capability metadata, without listing objects."""
    profile = plaintext_profile(platform_version)
    counter = secrets.randbelow(1000000000) + 1
    with socket.create_connection((host, port), timeout) as connection:
        channel = Channel(connection, timeout)
        channel.receive(greeting=True)
        creation = channel.request(creation_request(counter, profile.platform_version),
                                   stage='fingerprint creation')
        if (not isinstance(creation, list) or len(creation) != 2 or creation[1] != 0
                or not isinstance(creation[0], list) or len(creation[0]) < 4
                or creation[0][0] != 1 or not isinstance(creation[0][1], int)
                or creation[0][2] != 1):
            raise ValueError('Unexpected fingerprint creation reply')
        reference = tagged(creation[0][3], OBJECT_TAG)
        if not isinstance(reference, list) or len(reference) != 1:
            raise ValueError('Fingerprint did not receive a remote-object reference')
        object_id = str(uuid.UUID(reference[0]))
        capability = channel.request('{0,' + object_id + ',' + str(counter + 1)
                                     + ',1,' + INTERFACE + '}', stage='fingerprint capability')
        if (len(capability) != 1 or not isinstance(capability[0], list)
                or len(capability[0]) != 3 or capability[0][0] != 1
                or not isinstance(capability[0][1], int)
                or type(capability[0][2]) is not int
                or capability[0][2] < profile.minimum_methods):
            raise ValueError('Unexpected fingerprint capability reply')
        return {'profile': profile.name, 'family': profile.family,
                'platform-version': profile.platform_version,
                'interface-methods': capability[0][2]}


def fingerprint_agent(host, port=1540, timeout=10, platform_version='auto'):
    """Identify a native endpoint without credentials or administrative reads."""
    selected = BASELINE_VERSION if platform_version == 'auto' else platform_version
    try:
        result = _fingerprint_plaintext(host, port, timeout, selected)
    except NativeVersionMismatch as exc:
        if platform_version != 'auto':
            raise
        try:
            result = _fingerprint_plaintext(host, port, timeout, exc.server_version)
        except NativeVersionMismatch:
            raise
        except (ConnectionError, RemoteError, ValueError):
            family = ('protected-public-key' if exc.server_version in KNOWN_PROTECTED_VERSIONS
                      else 'unknown-native-profile')
            return {'endpoint': {'host': host, 'port': port},
                    'platform-version': exc.server_version, 'family': family,
                    'profile': None, 'interface-methods': None,
                    'administrative-requests-sent': 0,
                    'recommendation': 'Use ras_client.py through RAS for this endpoint.'}
    return {'endpoint': {'host': host, 'port': port}, **result,
            'administrative-requests-sent': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, default=1540)
    parser.add_argument('--platform-version', default='auto',
                        help='Native plaintext identity (default: discover and retry once)')
    parser.add_argument('--fingerprint', action='store_true',
                        help='Identify version/profile without credentials or administrative reads')
    parser.add_argument('--timeout', type=float, default=10)
    parser.add_argument('--cluster', help='Read only this cluster UUID')
    parser.add_argument('--infobase', help='Read only this infobase UUID; implies --infobases')
    parser.add_argument('--details', action='store_true', help='Retrieve full settings through server-directed worker connections')
    parser.add_argument('--worker-host', help='Override advertised worker hostname, preserving its port (for lab TCP relays)')
    parser.add_argument('--infobases', action='store_true', help='Also retrieve experimental infobase summaries directly on 1540')
    parser.add_argument('--sessions', action='store_true', help='List active sessions for selected/all infobases; implies --infobases')
    parser.add_argument('--cluster-user', default='', help='Cluster administrator name')
    parser.add_argument('--cluster-password-env', metavar='NAME', help='Read cluster password from this environment variable')
    parser.add_argument('--include-sensitive', action='store_true', help='Include credential-bearing and unmapped native settings in JSON output')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 0 < args.timeout <= 60: parser.error('Invalid port or timeout')
    if args.fingerprint:
        if (args.cluster or args.infobase or args.details or args.worker_host or args.infobases
                or args.sessions or args.cluster_user or args.cluster_password_env
                or args.include_sensitive):
            parser.error('--fingerprint cannot be combined with administrative read options')
        try:
            result = fingerprint_agent(args.host, args.port, args.timeout, args.platform_version)
        except (OSError, ValueError) as exc:
            parser.exit(1, str(exc) + '\n')
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    def password(user, variable, label):
        if variable:
            if variable not in os.environ: parser.error(label + ' password environment variable is unset')
            return os.environ[variable]
        if not user: return ''
        if not sys.stdin.isatty():
            parser.error('Interactive ' + label + ' password prompt requires a terminal; use --'
                         + label + '-password-env for automation')
        return getpass.getpass(label.capitalize() + ' administrator password: ')
    cluster_password = password(args.cluster_user, args.cluster_password_env, 'cluster')
    try: result = list_clusters(args.host, args.port, args.timeout, infobases=args.infobases,
                               details=args.details, sessions=args.sessions, worker_host=args.worker_host,
                               cluster_filter=args.cluster, infobase_filter=args.infobase,
                               cluster_user=args.cluster_user, cluster_password=cluster_password,
                               include_sensitive=args.include_sensitive,
                               platform_version=args.platform_version)
    except (OSError, ValueError) as exc: parser.exit(1, str(exc) + '\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__': main()
