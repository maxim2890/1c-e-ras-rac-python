"""Schema-driven RAS requests; independent of all 1C binaries and libraries.

The bundled schema is reference-derived unless the analysis report says otherwise.
No field defaults are invented for writes: every active field must be supplied.
"""
import datetime
import json
import math
from pathlib import Path
import struct
import uuid

from ras_client import Cursor, MAX_FRAME, ProtocolError, UnsupportedVersion, _date, varint, wire_string

SCHEMA = json.loads(Path(__file__).with_name('protocol_schema.json').read_text())
RECORDS = SCHEMA['records']
MESSAGES = {m['opcode']: m for m in SCHEMA['messages']}
REQUESTS = {m['name'].removesuffix('_REQUEST').lower().replace('_', '-'): m
            for m in SCHEMA['messages'] if m['direction'] == 'request'}
SECRET_FIELDS = frozenset(('password', 'pwd', 'dbPwd', 'dbPassword', 'deniedParameter',
                           'permissionCode', 'externalSessionManagerConnectionString'))
INTEGER_TYPES = {'int8': (1, True, 'big'), 'uint8': (1, False, 'big'),
                 'uint16': (2, False, 'big'), 'int32': (4, True, 'big'),
                 'int64': (8, True, 'big'), 'uint32le': (4, False, 'little')}
MAX_ITEMS = 10000


def spec(operation):
    try:
        return REQUESTS[operation]
    except KeyError:
        raise ValueError('Unknown schema operation') from None


def is_write(message):
    return not (message['name'].startswith(('GET_', 'AUTHENTICATE_', 'ADD_AUTHENTICATION_'))
                or message['name'] == 'BINARY_DATA_STORAGE_OPERATION_STATE_REQUEST')


def describe(operation):
    message = spec(operation)
    records = {}
    def visit(kind):
        if kind.startswith('list<'):
            visit(kind[5:-1])
        else:
            name = kind.removeprefix('ref:')
            if name in RECORDS and name not in records:
                records[name] = RECORDS[name]
                for field in RECORDS[name]['fields']:
                    visit(field['type'])
    for field in message.get('fields', []):
        visit(field['type'])
    response = message['response']
    response_spec = None if response == 'void' else MESSAGES[int(response.split(':')[1])]
    if response_spec:
        visit(response_spec['result'])
    return {'request': message, 'response': response_spec, 'records': records}


def _fields(fields, version):
    return [f for f in fields if f.get('since', 10) <= version]


def _record_fields(name, version):
    return _fields(RECORDS[name]['fields'], version)


def _encode_fields(fields, values, version):
    if not isinstance(values, dict):
        raise ValueError('Record must be a JSON object')
    active = _fields(fields, version)
    names = {f['name'] for f in active}
    if values.keys() != names:
        missing = sorted(names - values.keys())
        extra = sorted(values.keys() - names)
        raise ValueError(f'Wrong record fields: missing={missing}, extra={extra}')
    result = bytearray()
    for f in active:
        result.extend(encode(f['type'], values[f['name']], version))
        if len(result) > MAX_FRAME:
            raise ValueError('Request exceeds size limit')
    return bytes(result)


def encode(kind, value, version):
    if kind.startswith('ref:') or kind in RECORDS:
        name = kind.removeprefix('ref:')
        return _encode_fields(RECORDS[name]['fields'], value, version)
    if kind.startswith('list<'):
        if not isinstance(value, list) or len(value) > MAX_ITEMS:
            raise ValueError('Invalid list or too many items')
        result = bytearray(varint(len(value)))
        for item in value:
            result.extend(encode(kind[5:-1], item, version))
            if len(result) > MAX_FRAME:
                raise ValueError('Request exceeds size limit')
        return bytes(result)
    if kind == 'uuid':
        return uuid.UUID(str(value)).bytes
    if kind == 'string':
        if not isinstance(value, str):
            raise ValueError('String field requires text')
        return wire_string(value)
    if kind == 'bool':
        if not isinstance(value, bool):
            raise ValueError('Boolean field requires true or false')
        return bytes([int(value)])
    if kind in INTEGER_TYPES:
        if type(value) is not int:
            raise ValueError('Integer field requires an integer')
        size, signed, endian = INTEGER_TYPES[kind]
        try:
            return value.to_bytes(size, endian, signed=signed)
        except OverflowError:
            raise ValueError('Integer outside wire type range') from None
    if kind == 'double':
        if isinstance(value, bool) or not isinstance(value, (float, int)):
            raise ValueError('Double requires a finite number')
        try:
            converted = float(value)
        except OverflowError:
            raise ValueError('Double outside wire type range') from None
        if not math.isfinite(converted):
            raise ValueError('Double requires a finite number')
        return struct.pack('>d', converted)
    if kind == 'datetime':
        if value is None:
            raw = 0
        elif type(value) is int:
            raw = value
        else:
            date = datetime.datetime.fromisoformat(value)
            if date.tzinfo is not None:
                raise ValueError('1C datetime must be server-local time without timezone')
            delta = date - datetime.datetime(1, 1, 1)
            if delta.microseconds % 100:
                raise ValueError('1C datetime precision is 100 microseconds')
            raw = (delta.days * 86400 + delta.seconds) * 10000 + delta.microseconds // 100
        return encode('int64', raw, version)
    if kind == 'bytes3':
        if value != '000000':
            raise ValueError('Reserved padding must be hex 000000')
        return bytes(3)
    if kind == 'size':
        if type(value) is not int or not 0 <= value <= MAX_ITEMS:
            raise ValueError('Invalid list size')
        return varint(value)
    raise ProtocolError('Unsupported schema type: ' + kind)


def decode(kind, cursor, version, include_sensitive=False):
    if kind.startswith('ref:') or kind in RECORDS:
        result = {}
        for field in _record_fields(kind.removeprefix('ref:'), version):
            value = decode(field['type'], cursor, version, include_sensitive)
            if include_sensitive or field['name'] not in SECRET_FIELDS:
                result[field['name']] = value
        return result
    if kind.startswith('list<'):
        count = cursor.number()
        if count > MAX_ITEMS:
            raise ProtocolError('Too many result items')
        return [decode(kind[5:-1], cursor, version, include_sensitive) for _ in range(count)]
    if kind == 'uuid':
        return cursor.ident()
    if kind == 'string':
        return cursor.string()
    if kind == 'bool':
        return cursor.boolean()
    if kind in INTEGER_TYPES:
        size, signed, endian = INTEGER_TYPES[kind]
        return cursor.integer(size, signed, endian)
    if kind == 'double':
        value = struct.unpack('>d', cursor.take(8))[0]
        if not math.isfinite(value):
            raise ProtocolError('Non-finite double in response')
        return value
    if kind == 'datetime':
        return _date(cursor)
    if kind == 'bytes3':
        value = cursor.take(3)
        if value != bytes(3):
            raise ProtocolError('Unknown reserved record bytes')
        return value.hex()
    if kind == 'size':
        return cursor.number()
    raise ProtocolError('Unsupported schema type: ' + kind)


def prepare(operation, parameters, version):
    message = spec(operation)
    if version not in range(10, 23) or version < message.get('since', 10):
        raise UnsupportedVersion('Operation unavailable in selected schema version')
    payload = _encode_fields(message.get('fields', []), parameters, version)
    if len(payload) + 5 > MAX_FRAME:
        raise ValueError('Request exceeds frame size limit')
    return message, payload


def preview(operation, parameters, version):
    message, payload = prepare(operation, parameters, version)
    return {'operation': operation, 'protocol': f'{version}.0', 'opcode': message['opcode'],
            'modifies-server': is_write(message), 'encoded-body-bytes': len(payload),
            'required-authentication': message.get('auth', {}).get('requires', []),
            'response': message['response'], 'schema-confidence': 'reference-derived; see MODERN_ANALYSIS.md'}


def execute(client, operation, parameters, *, apply=False, agent_user='', agent_password='',
            cluster_user='', cluster_password='', infobase_user='', infobase_password='',
            include_sensitive=False):
    message, payload = prepare(operation, parameters, client.version)
    if is_write(message) and not apply:
        raise ValueError('Modifying requests require explicit apply=True / --apply')
    if is_write(message) and client.protocol == 'auto':
        raise ValueError('Modifying requests require an explicit --protocol to avoid schema downgrade')
    requirements = list(message.get('auth', {}).get('requires', []))
    if 'infobase' in message.get('auth', {}).get('optional', []) and (infobase_user or infobase_password):
        requirements.append('infobase')
    cluster = parameters.get('clusterId')
    # Validate all authorization inputs before sending anything.
    if any(r in requirements for r in ('cluster', 'infobase')):
        if cluster is None:
            raise ValueError('Operation authentication requires clusterId')
        cluster = str(uuid.UUID(str(cluster)))
    if 'agent' in requirements:
        client.authenticate_agent(agent_user, agent_password)
    if 'cluster' in requirements:
        client._auth(9, cluster, cluster_user, cluster_password)
    if 'infobase' in requirements:
        client._auth(10, cluster, infobase_user, infobase_password)
    response = message['response']
    expected = None if response == 'void' else int(response.split(':')[1])
    body = client._request(message['opcode'], payload, expected)
    if expected is None:
        return {'completed': True}
    kind = MESSAGES[expected]['result']
    cursor = Cursor(body)
    result = decode(kind, cursor, client.version, include_sensitive)
    cursor.finish(allow_zero=(message['opcode'] == 11 or
                              (client.version >= 22 and message['opcode'] in (0, 2, 118, 124))))
    return result
