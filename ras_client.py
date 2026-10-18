#!/usr/bin/env python3
"""Independent 1C RAS TCP client (Python standard library only).

Protocol facts cross-checked against python-rac (Platform42, MIT) and
alkoleft/v8_protocols captures. No 1C executable or library is loaded or run.
See THIRD_PARTY_NOTICES.txt for the reference implementation's MIT notice.
"""
import argparse
import datetime
import getpass
import json
import math
import os
import socket
import struct
import sys
import time
import uuid

MAX_FRAME = 4_000_000
SERVICE = b'v8.service.Admin.Cluster'
INIT = bytes.fromhex('1c535750010001000116010f636f6e6e6563742e74696d656f757404000007d0')
RPC_PREFIX = b'\x01\x00\x00\x01'
ACK = b'\x01\x00\x00\x00'
# 8.3.27.2342 advertises v8.service.Admin.Cluster 22.0.  The record layouts
# currently used by this client remain compatible with the observed 22.0
# cluster response; version-gated schema fields continue to apply normally.
SUPPORTED_VERSIONS = tuple(range(22, 9, -1))

class ProtocolError(ValueError):
    pass

class ServerError(ProtocolError):
    pass

class UnsupportedVersion(ProtocolError):
    pass

def varint(value, bits=7):
    if value < 0:
        raise ValueError('Negative unsigned integer')
    result = bytearray()
    group_bits = bits
    while value >= (1 << group_bits):
        result.append((value & ((1 << group_bits) - 1)) | (1 << group_bits))
        value >>= group_bits
        group_bits = 7
    result.append(value)
    return bytes(result)

def wire_string(value):
    data = value.encode('utf-8') if isinstance(value, str) else value
    if len(data) > MAX_FRAME:
        raise ValueError('String too long')
    return varint(len(data), 6) + data

def frame(opcode, payload):
    if len(payload) > MAX_FRAME:
        raise ProtocolError('Frame exceeds size limit')
    return bytes([opcode]) + varint(len(payload)) + payload

class Cursor:
    def __init__(self, data):
        self.data = memoryview(data)
        self.pos = 0

    def take(self, length):
        if length < 0 or self.pos + length > len(self.data):
            raise ProtocolError('Truncated record')
        result = self.data[self.pos:self.pos + length].tobytes()
        self.pos += length
        return result

    def number(self, bits=7):
        value = 0
        shift = 0
        group_bits = bits
        for index in range(4):
            byte = self.take(1)[0]
            if byte >= (1 << (group_bits + 1)):
                raise ProtocolError('Invalid variable integer')
            value |= (byte & ((1 << group_bits) - 1)) << shift
            if not byte & (1 << group_bits):
                if index and byte == 0:
                    raise ProtocolError('Noncanonical variable integer')
                if value > MAX_FRAME:
                    raise ProtocolError('Variable integer exceeds limit')
                return value
            shift += group_bits
            group_bits = 7
        raise ProtocolError('Variable integer too long')

    def string(self):
        # Native nullable UTF-8: 0x80 leaves a freshly initialized string empty.
        if self.pos < len(self.data) and self.data[self.pos] == 0x80:
            self.take(1)
            return ''
        try:
            return self.take(self.number(6)).decode('utf-8')
        except UnicodeDecodeError as exc:
            raise ProtocolError('Invalid UTF-8 string') from exc

    def integer(self, size=4, signed=True, endian='big'):
        return int.from_bytes(self.take(size), endian, signed=signed)

    def boolean(self):
        value = self.take(1)[0]
        if value not in (0, 1):
            raise ProtocolError('Invalid Boolean')
        return bool(value)

    def ident(self):
        return str(uuid.UUID(bytes=self.take(16)))

    def finish(self, allow_zero=False):
        remaining = self.take(len(self.data) - self.pos)
        if remaining and not (allow_zero and remaining == b'\x00'):
            raise ProtocolError('Unexpected bytes after record')


def decode_clusters(payload, version=16):
    c = Cursor(payload)
    count = c.number()
    if count > 1000:
        raise ProtocolError('Too many clusters')
    rows = []
    for _ in range(count):
        row = {'cluster': c.ident(), 'expiration-timeout': c.integer(), 'host': c.string(),
               'lifetime-limit': c.integer(), 'port': c.integer(2, False),
               'max-memory-size': c.integer(), 'max-memory-time-limit': c.integer(), 'name': c.string()}
        for name in ('security-level', 'session-fault-tolerance-level', 'load-balancing-mode', 'errors-count-threshold'):
            row[name] = c.integer()
        row['kill-problem-processes'] = c.boolean()
        row['kill-by-memory-with-dump'] = c.boolean()
        if version >= 14:
            row['_unknown-int32'] = c.integer()
        if version >= 15:
            row['allow-access-right-audit-events-recording'] = c.boolean()
            row['ping-period'] = c.integer()
            row['ping-timeout'] = c.integer()
            row['restart-schedule'] = c.string()
        if version >= 22:
            # 8.3.27.2342 appends a fixed 11-byte cluster policy tail that the
            # native RAC does not display. Preserve it as typed opaque values
            # until controlled mutations establish their semantics.
            row['_protocol-22-unknown-int32-a'] = c.integer()
            row['_protocol-22-unknown-uint8'] = c.integer(1, False)
            row['_protocol-22-unknown-int32-b'] = c.integer()
            row['_protocol-22-unknown-uint16'] = c.integer(2, False)
        rows.append(row)
    c.finish(allow_zero=True)
    if len({r['cluster'] for r in rows}) != count:
        raise ProtocolError('Duplicate cluster identifiers')
    return rows


def decode_summaries(payload):
    c = Cursor(payload)
    count = c.number()
    if count > 10000:
        raise ProtocolError('Too many infobases')
    rows = [{'infobase': c.ident(), 'descr': c.string(), 'name': c.string()} for _ in range(count)]
    c.finish()
    if len({r['infobase'] for r in rows}) != count:
        raise ProtocolError('Duplicate infobase identifiers')
    return rows


def _date(c):
    # 1C stores server-local wall time, with no timezone in the wire value.
    raw = c.integer(8)
    if not raw:
        return None
    try:
        return (datetime.datetime(1970, 1, 1)
                + datetime.timedelta(microseconds=(raw - 621355968000000) * 100)).isoformat()
    except OverflowError:
        return {'raw-1c-timestamp': raw}


def decode_infobase_info(payload, version=16, include_sensitive=False):
    c = Cursor(payload)
    row = {'infobase': c.ident(), 'date-offset': c.integer()}
    for name in ('dbms', 'db-name', 'db-pwd', 'db-server', 'db-user'):
        value = c.string()
        if name != 'db-pwd' or include_sensitive:
            row[name] = value
            if name == 'db-pwd' and value == '\ufffd':
                row['db-pwd-state'] = 'redacted-preserve-existing-sentinel'
    row['denied-from'] = _date(c)
    row['denied-message'] = c.string()
    denied_parameter = c.string()
    if include_sensitive:
        row['denied-parameter'] = denied_parameter
    row['denied-to'] = _date(c)
    for name in ('descr', 'locale', 'name'):
        row[name] = c.string()
    permission_code = c.string()
    if include_sensitive:
        row['permission-code'] = permission_code
    row['scheduled-jobs-deny'] = c.boolean()
    row['security-level'] = c.integer()
    row['sessions-deny'] = c.boolean()
    row['license-distribution'] = c.integer()
    manager_connection = c.string()
    if include_sensitive:
        row['external-session-manager-connection-string'] = manager_connection
    row['external-session-manager-required'] = c.boolean()
    row['security-profile-name'] = c.string()
    row['safe-mode-security-profile-name'] = c.string()
    row['reserve-working-processes'] = c.boolean()
    if version >= 13:
        row['disable-local-speech-to-text'] = c.boolean()
    if version >= 14:
        if c.take(3) != bytes(3):
            raise ProtocolError('Unknown infobase tail layout')
        row['configuration-unload-delay-by-working-process-without-active-users'] = c.integer(4, False, 'little')
        row['minimum-scheduled-jobs-start-period-without-active-users'] = c.integer(4, False, 'little')
        row['maximum-scheduled-jobs-start-shift-without-active-users'] = c.integer(1, False)
    c.finish()
    return row

class RasClient:
    def __init__(self, host, port=1545, timeout=5, protocol='auto'):
        if not math.isfinite(timeout) or timeout <= 0 or not 1 <= port <= 65535:
            raise ValueError('Invalid timeout or port')
        self.host, self.port, self.timeout = host, port, timeout
        if str(protocol) not in ('auto', *(str(v) for v in SUPPORTED_VERSIONS), *(f'{v}.0' for v in SUPPORTED_VERSIONS)):
            raise ValueError('Supported protocols: auto or 10.0 through 22.0')
        self.protocol = protocol
        self.sock = None
        self.version = None
        self._deadline = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *args):
        self.close()

    def _recv(self, size):
        result = bytearray()
        while len(result) < size:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('RAS response timed out')
            self.sock.settimeout(remaining)
            part = self.sock.recv(size - len(result))
            if not part:
                raise ProtocolError('RAS closed the connection')
            result.extend(part)
        return bytes(result)

    def _read_frame(self):
        opcode = self._recv(1)[0]
        encoded = bytearray()
        for _ in range(4):
            encoded.extend(self._recv(1))
            if encoded[-1] < 128:
                size = Cursor(encoded).number()
                return opcode, self._recv(size)
        raise ProtocolError('Frame length too long')

    def _send(self, payload):
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('RAS request timed out')
        self.sock.settimeout(remaining)
        self.sock.sendall(payload)

    def connect(self):
        if self.sock is not None:
            return self
        versions = SUPPORTED_VERSIONS if self.protocol == 'auto' else (int(str(self.protocol).split('.')[0]),)
        for version in versions:
            try:
                self.sock = socket.create_connection((self.host, self.port), self.timeout)
                self._deadline = time.monotonic() + self.timeout
                self._send(INIT)
                if self._read_frame() != (2, b'\x80'):
                    raise ProtocolError('Invalid SWP connection acknowledgment')
                negotiation = wire_string(SERVICE) + wire_string(f'{version}.0')
                self._send(frame(11, negotiation + b'\x80'))
                opcode, body = self._read_frame()
                if opcode == 15:
                    c = Cursor(body)
                    if c.string() == SERVICE.decode() and c.string() == f'{version}.0' and b'UnsupportedService' in body:
                        raise UnsupportedVersion(f'RAS rejected protocol {version}.0')
                    raise ProtocolError('RAS rejected endpoint negotiation')
                if (opcode, body) != (12, negotiation + b'\x01\x80'):
                    raise ProtocolError('Invalid administrative endpoint acknowledgment')
                self.version = version
                return self
            except UnsupportedVersion:
                self.close()
            except BaseException:
                self.close()
                raise
        raise UnsupportedVersion('RAS supports none of the implemented schema versions (10.0 through 22.0)')

    def close(self):
        if self.sock is not None:
            try:
                self.sock.settimeout(min(self.timeout, 1))
                self.sock.sendall(frame(13, b'\x01'))
            except OSError:
                pass
            finally:
                self.sock.close()
                self.sock = None

    def _request(self, method, body=b'', expected=None):
        if self.sock is None:
            raise ProtocolError('Client is not connected')
        try:
            self._deadline = time.monotonic() + self.timeout
            self._send(frame(14, RPC_PREFIX + bytes([method]) + body))
            opcode, reply = self._read_frame()
            if opcode == 14 and (reply[:4] == b'\x01\x00\x00\xff' or reply[:5] == RPC_PREFIX + b'\xff'):
                # Error contents can contain credentials or connection strings. Keep opaque.
                raise ServerError('RAS rejected the request; check administrator credentials and access rights')
            if expected is None:
                if (opcode, reply) != (14, ACK):
                    raise ProtocolError('Unexpected RAS authentication response')
                return b''
            if opcode != 14 or reply[:5] != RPC_PREFIX + bytes([expected]):
                raise ProtocolError('Unexpected RAS response method or envelope')
            return reply[5:]
        except ServerError:
            # A complete remote error response preserves frame alignment.
            raise
        except (OSError, ProtocolError):
            # Partial or unexpected responses cannot safely serve another request.
            self.close()
            raise

    def authenticate_agent(self, user="", password=""):
        """Authenticate a server-agent administrator when required by RAS."""
        self._request(8, wire_string(user) + wire_string(password))

    def list_clusters(self):
        return decode_clusters(self._request(11, expected=12), self.version)

    def _auth(self, method, cluster, user='', password=''):
        self._request(method, uuid.UUID(str(cluster)).bytes + wire_string(user) + wire_string(password))

    def list_infobases(self, cluster, user='', password=''):
        self._auth(9, cluster, user, password)
        return decode_summaries(self._request(42, uuid.UUID(str(cluster)).bytes, 43))

    def get_infobase_summary(self, cluster, infobase, user='', password=''):
        """Query one infobase using native GetInfoBaseShortInfo (46 -> 47)."""
        cluster_id = uuid.UUID(str(cluster))
        infobase_id = uuid.UUID(str(infobase))
        self._auth(9, cluster_id, user, password)
        c = Cursor(self._request(46, cluster_id.bytes + infobase_id.bytes, 47))
        result = {'infobase': c.ident(), 'descr': c.string(), 'name': c.string()}
        c.finish()
        if result['infobase'] != str(infobase_id):
            raise ProtocolError('Infobase identifier does not match the request')
        return result

    def get_infobase_info(self, cluster, infobase, user='', password='', infobase_user='', infobase_password='',
                          include_sensitive=False):
        cluster = str(uuid.UUID(str(cluster)))
        infobase = str(uuid.UUID(str(infobase)))
        self._auth(9, cluster, user, password)
        self._auth(10, cluster, infobase_user, infobase_password)
        result = decode_infobase_info(self._request(48, uuid.UUID(str(cluster)).bytes + uuid.UUID(str(infobase)).bytes, 49),
                                      self.version, include_sensitive)
        if result['infobase'] != str(uuid.UUID(str(infobase))):
            raise ProtocolError('Infobase identifier does not match the request')
        return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host', help='RAS host, not the ragent/rmngr endpoint')
    p.add_argument('--port', type=int, default=1545)
    p.add_argument('--protocol', default='auto', choices=('auto', *(f'{v}.0' for v in SUPPORTED_VERSIONS)))
    p.add_argument('--timeout', type=float, default=5)
    p.add_argument('--cluster', help='Cluster UUID; otherwise discover all clusters')
    p.add_argument('--agent-user', default='')
    p.add_argument('--ask-agent-password', action='store_true')
    p.add_argument('--cluster-user', default='')
    p.add_argument('--ask-cluster-password', action='store_true')
    p.add_argument('--infobase-user', default='')
    p.add_argument('--ask-infobase-password', action='store_true')
    p.add_argument('--infobase', help='Only this infobase UUID')
    p.add_argument('--details', action='store_true', help='Retrieve full infobase settings')
    p.add_argument('--include-sensitive', action='store_true', help='Include credential-bearing response fields in JSON output')
    p.add_argument('--clusters-only', action='store_true')
    p.add_argument('--operation', help='Typed read operation, e.g. session.list (see --list-operations)')
    p.add_argument('--parameters', help='JSON file of typed operation parameters (entity keys such as cluster/server)')
    p.add_argument('--rpc', help='Schema request name, e.g. get-agent-version or update-infobase-short')
    p.add_argument('--request-file', help='JSON file of exact schema request fields (camelCase)')
    p.add_argument('--list-operations', action='store_true', help='Print operation catalog locally and exit')
    p.add_argument('--describe-rpc', help='Print request and nested record schemas locally and exit')
    p.add_argument('--preview', action='store_true', help='Validate --rpc request locally without connecting (explicit --protocol required)')
    p.add_argument('--apply', action='store_true', help='Send a modifying --rpc request; explicit --protocol required')
    args = p.parse_args(argv)
    from pathlib import Path
    if args.list_operations:
        from ras_operations import OPERATIONS
        from ras_rpc import REQUESTS, is_write
        print(json.dumps({'read-operations': {k: {'parameters': dict(v.parameters), 'minimum-protocol': v.minimum_version}
                                               for k, v in OPERATIONS.items()},
                          'schema-requests': {k: {'opcode': v['opcode'], 'minimum-protocol': v.get('since', 10),
                                                  'modifies-server': is_write(v)} for k, v in REQUESTS.items()}}, indent=2))
        return 0
    if args.describe_rpc:
        from ras_rpc import describe
        try:
            print(json.dumps(describe(args.describe_rpc), ensure_ascii=False, indent=2))
            return 0
        except ValueError as exc:
            p.error(str(exc))
    if args.operation and args.rpc:
        p.error('--operation and --rpc are mutually exclusive')
    if args.parameters and not args.operation:
        p.error('--parameters requires --operation')
    if args.request_file and not args.rpc:
        p.error('--request-file requires --rpc')
    if (args.apply or args.preview) and not args.rpc:
        p.error('--apply and --preview require --rpc')
    if (args.apply or args.preview) and args.protocol == 'auto':
        p.error('--apply and --preview require an explicit --protocol')
    if (args.operation or args.rpc) and (args.details or args.clusters_only or args.infobase):
        p.error('Operation mode cannot be combined with infobase discovery flags')
    parameters = {}
    if args.parameters or args.request_file:
        try:
            path = Path(args.parameters or args.request_file)
            if path.stat().st_size > MAX_FRAME:
                p.error('Parameter file exceeds size limit')
            parameters = json.loads(path.read_text())
            if not isinstance(parameters, dict):
                p.error('Parameters must be a JSON object')
        except (OSError, ValueError) as exc:
            p.error('Cannot read parameter file: ' + str(exc))
    if args.rpc:
        from ras_rpc import spec, is_write, preview
        try:
            message = spec(args.rpc)
            if is_write(message) and not (args.apply or args.preview):
                p.error('Modifying requests require --preview or --apply')
            if args.cluster:
                if 'clusterId' in parameters and parameters['clusterId'] != args.cluster:
                    p.error('--cluster conflicts with request clusterId')
                parameters['clusterId'] = args.cluster
            if args.preview:
                print(json.dumps(preview(args.rpc, parameters, int(args.protocol.split('.')[0])), indent=2))
                return 0
        except ValueError as exc:
            p.error(str(exc))
    if not args.host:
        p.error('--host is required for server requests')
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        p.error('--timeout must be a finite positive number')
    if not 1 <= args.port <= 65535:
        p.error('--port must be between 1 and 65535')
    if args.clusters_only and (args.details or args.infobase):
        p.error('--clusters-only cannot be combined with --details or --infobase')
    for field in ('cluster', 'infobase'):
        value = getattr(args, field)
        if value is not None:
            try:
                setattr(args, field, str(uuid.UUID(value)))
            except ValueError:
                p.error('--' + field + ' must be a UUID')
    agent_password = getpass.getpass('Agent administrator password: ') if args.ask_agent_password else os.environ.get('RAS_AGENT_PASSWORD', '')
    cluster_password = getpass.getpass('Cluster administrator password: ') if args.ask_cluster_password else os.environ.get('RAS_CLUSTER_PASSWORD', '')
    ib_password = getpass.getpass('Infobase administrator password: ') if args.ask_infobase_password else os.environ.get('RAS_INFOBASE_PASSWORD', '')
    try:
        with RasClient(args.host, args.port, args.timeout, args.protocol) as client:
            if args.agent_user or agent_password:
                client.authenticate_agent(args.agent_user, agent_password)
            if args.operation or args.rpc:
                if args.operation:
                    from ras_operations import execute, OPERATIONS
                    if args.cluster:
                        if 'cluster' in parameters and parameters['cluster'] != args.cluster:
                            raise ValueError('--cluster conflicts with operation cluster')
                        parameters['cluster'] = args.cluster
                    if args.operation not in OPERATIONS:
                        raise ValueError('Unknown read operation')
                    agent_scope = OPERATIONS[args.operation].auth == 'agent'
                    result = execute(client, args.operation,
                                     user=args.agent_user if agent_scope else args.cluster_user,
                                     password=agent_password if agent_scope else cluster_password,
                                     include_sensitive=args.include_sensitive, **parameters)
                else:
                    from ras_rpc import execute
                    result = execute(client, args.rpc, parameters, apply=args.apply,
                                     agent_user=args.agent_user, agent_password=agent_password,
                                     cluster_user=args.cluster_user, cluster_password=cluster_password,
                                     infobase_user=args.infobase_user, infobase_password=ib_password,
                                     include_sensitive=args.include_sensitive)
                print(json.dumps({'ras': {'host': args.host, 'port': args.port, 'protocol': f'{client.version}.0'},
                                  'operation': args.operation or args.rpc, 'result': result}, ensure_ascii=False, indent=2))
                return 0
            clusters = [{'cluster': str(uuid.UUID(args.cluster))}] if args.cluster else client.list_clusters()
            if not args.clusters_only:
                for cluster in clusters:
                    if args.cluster and args.infobase:
                        if args.details:
                            rows = [client.get_infobase_info(args.cluster, args.infobase, args.cluster_user, cluster_password,
                                                           args.infobase_user, ib_password, args.include_sensitive)]
                        else:
                            rows = [client.get_infobase_summary(args.cluster, args.infobase, args.cluster_user, cluster_password)]
                    else:
                        rows = client.list_infobases(cluster['cluster'], args.cluster_user, cluster_password)
                        if args.infobase:
                            rows = [row for row in rows if row['infobase'] == args.infobase]
                        if args.details:
                            rows = [client.get_infobase_info(cluster['cluster'], row['infobase'], args.cluster_user, cluster_password,
                                                            args.infobase_user, ib_password, args.include_sensitive) for row in rows]
                    cluster['infobases'] = rows
                if args.infobase and not any(c['infobases'] for c in clusters):
                    raise ProtocolError('Requested infobase was not listed')
            print(json.dumps({'ras': {'host': args.host, 'port': args.port, 'protocol': f'{client.version}.0'}, 'clusters': clusters}, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
