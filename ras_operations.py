"""Typed, read-only RAS operations using the independent transport.

Record layouts and method IDs derive from Platform42 python-rac 0.7.1's
MIT-licensed protocol schema; see THIRD_PARTY_NOTICES.txt. No proprietary
executable, library, source implementation, or runtime dependency is used.
Schemas target endpoint protocols 10.0 through 22.0. This does not claim
live-server validation of every operation or version.
"""
from dataclasses import dataclass
import math
import struct
import uuid
from types import MappingProxyType

from ras_client import Cursor, ProtocolError, UnsupportedVersion, _date, wire_string

MAX_ITEMS = 10000
# Each field is (JSON key, wire type, minimum endpoint version).
# None means a password-bearing response field. It is omitted unless the
# caller explicitly requests sensitive output.
SCHEMAS = {
    'AssignmentRuleInfo': (
        ('rule', 'uuid', 10),
        ('object-type', 'string', 10),
        ('infobase-name', 'string', 10),
        ('rule-type', 'int32', 10),
        ('application-ext', 'string', 10),
        ('priority', 'int32', 10),
    ),
    'BinaryDataStorageInfo': (
        ('storage', 'uuid', 16),
        ('name', 'string', 16),
        ('kind', 'int32', 16),
    ),
    'ClusterManagerInfo': (
        ('manager', 'uuid', 10),
        ('descr', 'string', 10),
        ('host', 'string', 10),
        ('using', 'int32', 10),
        ('port', 'uint16', 10),
        ('pid', 'string', 10),
    ),
    'ClusterServiceInfo': (
        ('name', 'string', 10),
        ('descr', 'string', 10),
        ('main-only', 'int32', 10),
        ('manager', 'list<uuid>', 10),
        ('_protocol-22-unknown-int32', 'int32', 22),
    ),
    'InfoBaseConnectionInfo': (
        ('connection', 'uuid', 10),
        ('app-id', 'string', 10),
        ('blocked-by-dbms', 'int32', 10),
        ('bytes-all', 'int64', 10),
        ('bytes-last-5min', 'int64', 10),
        ('calls-all', 'int64', 10),
        ('calls-last-5min', 'int64', 10),
        ('connected-at', 'datetime', 10),
        ('conn-id', 'int32', 10),
        ('db-conn-mode', 'int32', 10),
        ('dbms-bytes-all', 'int64', 10),
        ('dbms-bytes-last-5min', 'int64', 10),
        ('db-proc-info', 'string', 10),
        ('db-proc-took', 'int32', 10),
        ('db-proc-took-at', 'datetime', 10),
        ('duration-all', 'int32', 10),
        ('duration-all-dbms', 'int32', 10),
        ('duration-current', 'int32', 10),
        ('duration-current-dbms', 'int32', 10),
        ('duration-last-5min', 'int64', 10),
        ('duration-last-5min-dbms', 'int64', 10),
        ('host', 'string', 10),
        ('ib-conn-mode', 'int32', 10),
        ('thread-mode', 'int32', 10),
        ('user-name', 'string', 10),
        ('memory-current', 'int64', 10),
        ('memory-last-5min', 'int64', 10),
        ('memory-total', 'int64', 10),
        ('read-current', 'int64', 10),
        ('read-last-5min', 'int64', 10),
        ('read-total', 'int64', 10),
        ('write-current', 'int64', 10),
        ('write-last-5min', 'int64', 10),
        ('write-total', 'int64', 10),
        ('duration-current-service', 'int32', 10),
        ('duration-last-5min-service', 'int64', 10),
        ('duration-all-service', 'int32', 10),
        ('current-service-name', 'string', 10),
    ),
    'InfoBaseConnectionShort': (
        ('connection', 'uuid', 10),
        ('application', 'string', 10),
        ('blocked-by-ls', 'int32', 10),
        ('connected-at', 'datetime', 10),
        ('conn-id', 'int32', 10),
        ('host', 'string', 10),
        ('infobase', 'uuid', 10),
        ('process', 'uuid', 10),
        ('session-number', 'int32', 10),
    ),
    'LicenseInfo': (
        ('full-name', 'string', 10),
        ('full-presentation', 'string', 10),
        ('issued-by-server', 'bool', 10),
        ('license-type', 'int32', 10),
        ('max-users-all', 'int32', 10),
        ('max-users-cur', 'int32', 10),
        ('net', 'bool', 10),
        ('rmngr-address', 'string', 10),
        ('rmngr-pid', 'string', 10),
        ('rmngr-port', 'int32', 10),
        ('series', 'string', 10),
        ('short-presentation', 'string', 10),
    ),
    'ObjectLock': (
        ('connection', 'uuid', 10),
        ('lock-descr', 'string', 10),
        ('locked-at', 'datetime', 10),
        ('object', 'uuid', 10),
        ('sid', 'uuid', 10),
    ),
    'PortRangeInfo': (
        ('high-bound', 'uint16', 10),
        ('low-bound', 'uint16', 10),
    ),
    'RegUserInfo': (
        ('name', 'string', 10),
        ('descr', 'string', 10),
        (None, 'string', 10),
        ('auth=pwd', 'bool', 10),
        ('auth=os', 'bool', 10),
        ('os-user', 'string', 10),
    ),
    'ResourceConsumptionCounter': (
        ('name', 'string', 10),
        ('collection-time', 'int64', 10),
        ('group', 'int8', 10),
        ('filter-type', 'int8', 10),
        ('filter', 'string', 10),
        ('duration', 'bool', 10),
        ('cpu-time', 'bool', 10),
        ('duration-dbms', 'bool', 10),
        ('service', 'bool', 10),
        ('memory', 'bool', 10),
        ('read', 'bool', 10),
        ('write', 'bool', 10),
        ('dbms-bytes', 'bool', 10),
        ('call', 'bool', 10),
        ('number-of-active-sessions', 'bool', 10),
        ('number-of-sessions', 'bool', 10),
        ('descr', 'string', 10),
    ),
    'ResourceConsumptionCounterValue': (
        ('object', 'string', 10),
        ('collection-time', 'int64', 10),
        ('duration', 'int64', 10),
        ('cpu-time', 'int64', 10),
        ('duration-dbms', 'int64', 10),
        ('duration-service', 'int64', 10),
        ('memory', 'int64', 10),
        ('read-bytes', 'int64', 10),
        ('write-bytes', 'int64', 10),
        ('dbms-bytes', 'int64', 10),
        ('calls', 'int64', 10),
        ('active-session-count', 'int64', 10),
        ('session-count', 'int64', 10),
        ('time', 'datetime', 10),
    ),
    'ResourceConsumptionLimit': (
        ('name', 'string', 10),
        ('counter', 'string', 10),
        ('action', 'uint8', 10),
        ('duration', 'int64', 10),
        ('cpu-time', 'int64', 10),
        ('duration-dbms', 'int64', 10),
        ('service', 'int64', 10),
        ('memory', 'int64', 10),
        ('read', 'int64', 10),
        ('write', 'int64', 10),
        ('dbms-bytes', 'int64', 10),
        ('call', 'int64', 10),
        ('number-of-active-sessions', 'int64', 10),
        ('number-of-sessions', 'int64', 10),
        ('error-message', 'string', 10),
        ('descr', 'string', 10),
    ),
    'SecurityProfile': (
        ('name', 'string', 10),
        ('descr', 'string', 10),
        ('file-system-full-access', 'bool', 10),
        ('com-use-full-access', 'bool', 10),
        ('add-in-use-full-access', 'bool', 10),
        ('external-app-full-access', 'bool', 10),
        ('internet-use-full-access', 'bool', 10),
        ('config', 'bool', 10),
        ('priv', 'bool', 10),
        ('unsafe-external-module-full-access', 'bool', 10),
        ('crypto', 'bool', 10),
        ('right-extension', 'bool', 10),
        ('right-extension-definition-roles', 'string', 10),
        ('all-modules-extension', 'bool', 10),
        ('modules-available-for-extension', 'string', 10),
        ('modules-not-available-for-extension', 'string', 10),
        ('privileged-mode-roles', 'string', 10),
    ),
    'SecurityProfileAddIn': (
        ('sp-name', 'string', 10),
        ('name', 'string', 10),
        ('add-in-hash', 'string', 10),
        ('descr', 'string', 10),
    ),
    'SecurityProfileApplication': (
        ('sp-name', 'string', 10),
        ('name', 'string', 10),
        ('command-wild', 'string', 10),
        ('descr', 'string', 10),
    ),
    'SecurityProfileCOMClass': (
        ('sp-name', 'string', 10),
        ('name', 'string', 10),
        ('file-name', 'string', 10),
        ('object-uuid', 'string', 10),
        ('computer-name', 'string', 10),
        ('descr', 'string', 10),
    ),
    'SecurityProfileExternalModule': (
        ('sp-name', 'string', 10),
        ('name', 'string', 10),
        ('module-hash', 'string', 10),
        ('descr', 'string', 10),
    ),
    'SecurityProfileInternetResource': (
        ('sp-name', 'string', 10),
        ('name', 'string', 10),
        ('address', 'string', 10),
        ('port', 'int32', 10),
        ('protocol', 'string', 10),
        ('descr', 'string', 10),
    ),
    'SecurityProfileVirtualDirectory': (
        ('sp-name', 'string', 10),
        ('alias', 'string', 10),
        ('physical-path', 'string', 10),
        ('allowed-read', 'bool', 10),
        ('allowed-write', 'bool', 10),
        ('descr', 'string', 10),
    ),
    'ServiceDataDirForTransfer': (
        ('service-name', 'string', 16),
        ('info-base-name', 'string', 16),
        ('from-dir', 'string', 16),
        ('to-dir', 'string', 16),
    ),
    'ServiceSetting': (
        ('setting', 'uuid', 16),
        ('service-name', 'string', 16),
        ('infobase-name', 'string', 16),
        ('service-data-dir', 'string', 16),
        ('active', 'bool', 16),
        ('_unknown-byte', 'uint8', 16),
    ),
    'SessionInfo': (
        ('session-id', 'uuid', 10),
        ('app-id', 'string', 10),
        ('blocked-by-dbms', 'int32', 10),
        ('blocked-by-ls', 'int32', 10),
        ('bytes-all', 'int64', 10),
        ('bytes-last-5min', 'int64', 10),
        ('calls-all', 'int32', 10),
        ('calls-last-5min', 'int64', 10),
        ('connection', 'uuid', 10),
        ('dbms-bytes-all', 'int64', 10),
        ('dbms-bytes-last-5min', 'int64', 10),
        ('db-proc-info', 'string', 10),
        ('db-proc-took', 'int32', 10),
        ('db-proc-took-at', 'datetime', 10),
        ('duration-all', 'int32', 10),
        ('duration-all-dbms', 'int32', 10),
        ('duration-current', 'int32', 10),
        ('duration-current-dbms', 'int32', 10),
        ('duration-last-5min', 'int64', 10),
        ('duration-last-5min-dbms', 'int64', 10),
        ('host', 'string', 10),
        ('infobase', 'uuid', 10),
        ('last-active-at', 'datetime', 10),
        ('hibernate', 'bool', 10),
        ('passive-session-hibernate-time', 'int32', 10),
        ('hibernate-session-terminate-time', 'int32', 10),
        ('licenses', 'list<LicenseInfo>', 10),
        ('locale', 'string', 10),
        ('process', 'uuid', 10),
        ('session-number', 'int32', 10),
        ('started-at', 'datetime', 10),
        ('user-name', 'string', 10),
        ('memory-current', 'int64', 10),
        ('memory-last-5min', 'int64', 10),
        ('memory-total', 'int64', 10),
        ('read-bytes-current', 'int64', 10),
        ('read-bytes-last-5min', 'int64', 10),
        ('read-bytes-total', 'int64', 10),
        ('write-bytes-current', 'int64', 10),
        ('write-bytes-last-5min', 'int64', 10),
        ('write-bytes-total', 'int64', 10),
        ('duration-current-service', 'int32', 10),
        ('duration-last-5min-service', 'int64', 10),
        ('duration-all-service', 'int32', 10),
        ('current-service-name', 'string', 10),
        ('cpu-time-current', 'int64', 10),
        ('cpu-time-last-5min', 'int64', 10),
        ('cpu-time-all', 'int64', 10),
        ('data-separation', 'string', 10),
        ('client-ip-address', 'string', 10),
    ),
    'WorkingProcessInfo': (
        ('process', 'uuid', 10),
        ('avg-back-call-time', 'double', 10),
        ('avg-call-time', 'double', 10),
        ('avg-db-call-time', 'double', 10),
        ('avg-lock-call-time', 'double', 10),
        ('avg-server-call-time', 'double', 10),
        ('avg-threads', 'double', 10),
        ('capacity', 'int32', 10),
        ('connections', 'int32', 10),
        ('host', 'string', 10),
        ('turned-on', 'bool', 10),
        ('licenses', 'list<LicenseInfo>', 10),
        ('port', 'uint16', 10),
        ('memory-excess-time', 'int32', 10),
        ('memory-size', 'int32', 10),
        ('pid', 'string', 10),
        ('running', 'int32', 10),
        ('selection-size', 'int32', 10),
        ('started-at', 'datetime', 10),
        ('use', 'int32', 10),
        ('available-perfomance', 'int32', 10),
        ('reserve', 'bool', 10),
    ),
    'WorkingServerInfo': (
        ('server', 'uuid', 10),
        ('agent-host', 'string', 10),
        ('agent-port', 'uint16', 10),
        ('name', 'string', 10),
        ('using', 'bool', 10),
        ('safe-working-processes-memory-limit', 'int64', 10),
        ('safe-call-memory-limit', 'int64', 10),
        ('infobases-limit', 'int32', 10),
        ('memory-limit', 'int64', 10),
        ('connections-limit', 'int32', 10),
        ('cluster-port', 'uint16', 10),
        ('dedicate-managers', 'bool', 10),
        ('port-range', 'list<PortRangeInfo>', 10),
        ('critical-total-memory', 'int64', 10),
        ('temporary-allowed-total-memory', 'int64', 10),
        ('temporary-allowed-total-memory-time-limit', 'int64', 10),
        ('service-principal-name', 'string', 11),
        ('_unknown-byte', 'uint8', 12),
        ('restart-schedule', 'string', 16),
        # 8.3.27 / service protocol 22 appends six bytes.  Native rac does not
        # print names for these values, so preserve their types and positions
        # without assigning unsupported semantics.
        ('_protocol-22-unknown-bool-a', 'bool', 22),
        ('_protocol-22-unknown-int32', 'int32', 22),
        ('_protocol-22-unknown-bool-b', 'bool', 22),
    ),
}

@dataclass(frozen=True)
class Operation:
    request: int
    response: int
    result: str
    parameters: tuple
    auth: str = 'cluster'
    minimum_version: int = 10
    identity_key: str | None = None
    identity_parameter: str | None = None

# Immutable allowlist: no arbitrary method number or mutating request entry point.
OPERATIONS = MappingProxyType({
    'agent.admin.list': Operation(0, 1, 'list<RegUserInfo>', (), 'agent', 10, None, None),
    'cluster.admin.list': Operation(2, 3, 'list<RegUserInfo>', (('cluster', 'uuid'),), 'cluster', 10, None, None),
    'manager.list': Operation(18, 19, 'list<ClusterManagerInfo>', (('cluster', 'uuid'),), 'cluster', 10, None, None),
    'manager.info': Operation(20, 21, 'ClusterManagerInfo', (('cluster', 'uuid'), ('manager', 'uuid')), 'cluster', 10, 'manager', 'manager'),
    'server.list': Operation(22, 23, 'list<WorkingServerInfo>', (('cluster', 'uuid'),), 'cluster', 10, None, None),
    'server.info': Operation(24, 25, 'WorkingServerInfo', (('cluster', 'uuid'), ('server', 'uuid')), 'cluster', 10, 'server', 'server'),
    'process.list': Operation(29, 30, 'list<WorkingProcessInfo>', (('cluster', 'uuid'),), 'cluster', 10, None, None),
    'process.info': Operation(31, 32, 'WorkingProcessInfo', (('cluster', 'uuid'), ('process', 'uuid')), 'cluster', 10, 'process', 'process'),
    'process.list-by-server': Operation(33, 34, 'list<WorkingProcessInfo>', (('cluster', 'uuid'), ('server', 'uuid')), 'cluster', 10, None, None),
    'service.list': Operation(35, 36, 'list<ClusterServiceInfo>', (('cluster', 'uuid'),), 'cluster', 10, None, None),
    'connection.list': Operation(50, 51, 'list<InfoBaseConnectionShort>', (('cluster', 'uuid'),), 'cluster', 10, None, None),
    'connection.list-by-infobase': Operation(52, 53, 'list<InfoBaseConnectionShort>', (('cluster', 'uuid'), ('infobase', 'uuid')), 'cluster', 10, None, None),
    'connection.info': Operation(54, 55, 'InfoBaseConnectionShort', (('cluster', 'uuid'), ('connection', 'uuid')), 'cluster', 10, 'connection', 'connection'),
    'connection.list-by-process': Operation(56, 57, 'list<InfoBaseConnectionInfo>', (('cluster', 'uuid'), ('process', 'uuid'), ('infobase', 'uuid')), 'cluster', 10, None, None),
    'session.list': Operation(65, 66, 'list<SessionInfo>', (('cluster', 'uuid'),), 'cluster', 10, None, None),
    'session.list-by-infobase': Operation(67, 68, 'list<SessionInfo>', (('cluster', 'uuid'), ('infobase', 'uuid')), 'cluster', 10, None, None),
    'session.info': Operation(69, 70, 'SessionInfo', (('cluster', 'uuid'), ('session', 'uuid')), 'cluster', 10, 'session-id', 'session'),
    'lock.list': Operation(72, 73, 'list<ObjectLock>', (('cluster', 'uuid'),), 'cluster', 10, None, None),
    'lock.list-by-infobase': Operation(74, 75, 'list<ObjectLock>', (('cluster', 'uuid'), ('infobase', 'uuid')), 'cluster', 10, None, None),
    'lock.list-by-connection': Operation(76, 77, 'list<ObjectLock>', (('cluster', 'uuid'), ('connection', 'uuid')), 'cluster', 10, None, None),
    'lock.list-by-session': Operation(78, 79, 'list<ObjectLock>', (('cluster', 'uuid'), ('infobase', 'uuid'), ('session', 'uuid')), 'cluster', 10, None, None),
    'rule.list': Operation(85, 86, 'list<AssignmentRuleInfo>', (('cluster', 'uuid'), ('server', 'uuid')), 'cluster', 10, None, None),
    'rule.info': Operation(87, 88, 'AssignmentRuleInfo', (('cluster', 'uuid'), ('server', 'uuid'), ('rule', 'uuid')), 'cluster', 10, 'rule', 'rule'),
    'profile.list': Operation(89, 90, 'list<SecurityProfile>', (('cluster', 'uuid'),), 'cluster', 10, None, None),
    'profile.directory.list': Operation(93, 94, 'list<SecurityProfileVirtualDirectory>', (('cluster', 'uuid'), ('profile', 'string')), 'cluster', 10, None, None),
    'profile.com.list': Operation(97, 98, 'list<SecurityProfileCOMClass>', (('cluster', 'uuid'), ('profile', 'string')), 'cluster', 10, None, None),
    'profile.addin.list': Operation(101, 102, 'list<SecurityProfileAddIn>', (('cluster', 'uuid'), ('profile', 'string')), 'cluster', 10, None, None),
    'profile.module.list': Operation(105, 106, 'list<SecurityProfileExternalModule>', (('cluster', 'uuid'), ('profile', 'string')), 'cluster', 10, None, None),
    'profile.app.list': Operation(109, 110, 'list<SecurityProfileApplication>', (('cluster', 'uuid'), ('profile', 'string')), 'cluster', 10, None, None),
    'profile.internet.list': Operation(113, 114, 'list<SecurityProfileInternetResource>', (('cluster', 'uuid'), ('profile', 'string')), 'cluster', 10, None, None),
    'counter.list': Operation(118, 119, 'list<ResourceConsumptionCounter>', (('cluster', 'uuid'),), 'cluster', 10, None, None),
    'counter.info': Operation(120, 121, 'ResourceConsumptionCounter', (('cluster', 'uuid'), ('name', 'string')), 'cluster', 10, 'name', 'name'),
    'limit.list': Operation(124, 125, 'list<ResourceConsumptionLimit>', (('cluster', 'uuid'),), 'cluster', 10, None, None),
    'limit.info': Operation(126, 127, 'ResourceConsumptionLimit', (('cluster', 'uuid'), ('name', 'string')), 'cluster', 10, 'name', 'name'),
    'counter.values': Operation(130, 131, 'list<ResourceConsumptionCounterValue>', (('cluster', 'uuid'), ('name', 'string'), ('object', 'string')), 'cluster', 10, None, None),
    'counter.accumulated-values': Operation(133, 134, 'list<ResourceConsumptionCounterValue>', (('cluster', 'uuid'), ('name', 'string'), ('object', 'string')), 'cluster', 10, None, None),
    'agent.version': Operation(135, 136, 'string', (), 'none', 10, None, None),
    'service-setting.info': Operation(137, 138, 'ServiceSetting', (('cluster', 'uuid'), ('server', 'uuid'), ('setting', 'uuid')), 'cluster', 16, 'setting', 'setting'),
    'service-setting.list': Operation(139, 140, 'list<ServiceSetting>', (('cluster', 'uuid'), ('server', 'uuid')), 'cluster', 16, None, None),
    'service-setting.data-dirs': Operation(145, 146, 'list<ServiceDataDirForTransfer>', (('cluster', 'uuid'), ('server', 'uuid'), ('service', 'string')), 'cluster', 16, None, None),
    'service-setting.by-params': Operation(147, 148, 'ServiceSetting', (('cluster', 'uuid'), ('server', 'uuid'), ('service', 'string'), ('infobase_name', 'string')), 'cluster', 16, None, None),
    'binary-data-storage.list': Operation(153, 160, 'list<BinaryDataStorageInfo>', (('cluster', 'uuid'), ('infobase', 'uuid')), 'cluster', 16, None, None),
})


def _count(c):
    count = c.number()
    if count > MAX_ITEMS:
        raise ProtocolError('Too many records in response')
    return count


def _read(c, kind, version, include_sensitive=False):
    if kind == 'string':
        return c.string()
    if kind == 'uuid':
        return c.ident()
    if kind == 'bool':
        return c.boolean()
    if kind == 'datetime':
        return _date(c)
    if kind == 'double':
        value = struct.unpack('>d', c.take(8))[0]
        if not math.isfinite(value):
            raise ProtocolError('Nonfinite floating point field')
        return value
    numeric = {'int8': (1, True, 'big'), 'uint8': (1, False, 'big'),
               'uint16': (2, False, 'big'), 'int32': (4, True, 'big'),
               'int64': (8, True, 'big'), 'uint32le': (4, False, 'little')}
    if kind in numeric:
        return c.integer(*numeric[kind])
    if kind.startswith('list<'):
        inner = kind[5:-1]
        count = _count(c)
        return [_read(c, inner, version, include_sensitive) for _ in range(count)]
    if kind not in SCHEMAS:
        raise ProtocolError('Unsupported record schema')
    row = {}
    for key, field_kind, since in SCHEMAS[kind]:
        if version >= since:
            value = _read(c, field_kind, version, include_sensitive)
            output_key = 'password' if key is None and kind == 'RegUserInfo' else key
            if output_key is not None and (key is not None or include_sensitive):
                row[output_key] = value
                if field_kind == 'list<LicenseInfo>':
                    row['license-count'] = len(value)
    return row


def decode(result, payload, version, include_sensitive=False, allow_zero=False):
    """Decode an RPC body, excluding its five-byte message envelope."""
    if version not in range(10, 23):
        raise UnsupportedVersion('Typed operation schemas support 10.0 through 22.0')
    c = Cursor(payload)
    row = _read(c, result, version, include_sensitive)
    c.finish(allow_zero=allow_zero)
    return row


def execute(client, operation, *, user='', password='', object_id=None, include_sensitive=False, **arguments):
    """Run an allowlisted read operation with all arguments validated before I/O.

    Parameter names and wire order are available as OPERATIONS[name].parameters.
    UUID parameters use their entity name (cluster/server/session/etc). object_id
    aliases a single noncluster UUID parameter for simple CLI integrations.
    user/password authenticate the cluster, or agent for agent.admin.list.
    Agent authentication for other operations may be done once on the client.
    """
    if operation not in OPERATIONS:
        raise ValueError('Unknown read operation: ' + str(operation))
    spec = OPERATIONS[operation]
    version = client.version
    if version not in range(10, 23) or version < spec.minimum_version:
        raise UnsupportedVersion('Operation unavailable for the negotiated endpoint version')
    if object_id is not None:
        targets = [name for name, kind in spec.parameters if kind == 'uuid' and name != 'cluster']
        if len(targets) != 1 or targets[0] in arguments:
            raise ValueError('object_id requires exactly one unassigned object UUID parameter')
        arguments[targets[0]] = object_id
    required = {name for name, _ in spec.parameters}
    if set(arguments) != required:
        missing = required - set(arguments)
        extra = set(arguments) - required
        raise ValueError('Operation parameters mismatch: missing=' + ','.join(sorted(missing)) + '; unexpected=' + ','.join(sorted(extra)))
    normalized = {}
    parts = []
    for name, kind in spec.parameters:
        value = arguments[name]
        if kind == 'uuid':
            value = str(uuid.UUID(str(value)))
            parts.append(uuid.UUID(value).bytes)
        elif kind == 'string':
            if not isinstance(value, str):
                raise ValueError(name + ' must be text')
            parts.append(wire_string(value))
        else:
            raise ValueError('Unsupported request parameter type')
        normalized[name] = value
    # Validate credentials' encoding/size before any authentication round trip.
    wire_string(user)
    wire_string(password)
    if spec.auth == 'cluster':
        client._auth(9, normalized['cluster'], user, password)
    elif spec.auth == 'agent':
        client.authenticate_agent(user, password)
    payload = client._request(spec.request, b''.join(parts), expected=spec.response)
    # Protocol 22 adds a zero-valued secondary-list/presence trailer to these
    # list responses. Its semantic name is not exposed by native rac.
    allow_zero = version >= 22 and spec.request in (0, 2, 118, 124)
    result = decode(spec.result, payload, version, include_sensitive, allow_zero)
    if spec.identity_key is not None and result.get(spec.identity_key) != normalized[spec.identity_parameter]:
        raise ProtocolError('Response identifier does not match requested object')
    return result
