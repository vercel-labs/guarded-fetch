import dgram from 'node:dgram';

import ipaddr from 'ipaddr.js';

/** How the stub answers queries for one name. */
export interface StubRecord {
  A?: string[];
  AAAA?: string[];
  ttl?: number;
  /** Never answer, like a nameserver that drops packets. */
  blackhole?: boolean;
}

export interface DnsStubServer {
  /** `host:port` for `dns.setServers()`. */
  address: string;
  records: Map<string, StubRecord>;
  /** Query counts keyed by `name/A` or `name/AAAA`. */
  queries: Map<string, number>;
  close: () => Promise<void>;
}

const TYPE_A = 1;
const TYPE_AAAA = 28;
const RCODE_NXDOMAIN = 3;

/**
 * A minimal UDP DNS server for tests: answers A/AAAA queries from `records`,
 * replies NXDOMAIN for unknown names, and stays silent for blackholed ones.
 */
export async function startDnsStubServer(): Promise<DnsStubServer> {
  const socket = dgram.createSocket('udp4');
  const records = new Map<string, StubRecord>();
  const queries = new Map<string, number>();

  socket.on('message', (packet, remote) => {
    const question = parseQuestion(packet);
    if (!question) {
      return;
    }
    const { name, type, end } = question;
    const typeName = type === TYPE_AAAA ? 'AAAA' : 'A';
    const key = `${name}/${typeName}`;
    queries.set(key, (queries.get(key) ?? 0) + 1);

    const record = records.get(name);
    if (record?.blackhole) {
      return;
    }
    const answers =
      type === TYPE_A || type === TYPE_AAAA ? (record?.[typeName] ?? []) : [];
    socket.send(
      buildResponse(packet, end, type, answers, record?.ttl ?? 60, !record),
      remote.port,
      remote.address,
    );
  });

  await new Promise<void>((resolve) => {
    socket.bind(0, '127.0.0.1', resolve);
  });

  return {
    address: `127.0.0.1:${socket.address().port}`,
    records,
    queries,
    close: () =>
      new Promise<void>((resolve) => {
        socket.close(() => resolve());
      }),
  };
}

function parseQuestion(
  packet: Buffer,
): { name: string; type: number; end: number } | undefined {
  const labels: string[] = [];
  let offset = 12;
  while (offset < packet.length) {
    const length = packet[offset] ?? 0;
    offset += 1;
    if (length === 0) {
      break;
    }
    labels.push(packet.toString('ascii', offset, offset + length));
    offset += length;
  }
  if (offset + 4 > packet.length) {
    return undefined;
  }
  return {
    name: labels.join('.').toLowerCase(),
    type: packet.readUInt16BE(offset),
    end: offset + 4,
  };
}

function buildResponse(
  query: Buffer,
  questionEnd: number,
  type: number,
  answers: string[],
  ttl: number,
  nxdomain: boolean,
): Buffer {
  const header = Buffer.alloc(12);
  query.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8180 | (nxdomain ? RCODE_NXDOMAIN : 0), 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answers.length, 6);

  const records = answers.map((address) => {
    const rdata = Buffer.from(ipaddr.parse(address).toByteArray());
    const record = Buffer.alloc(12);
    record.writeUInt16BE(0xc00c, 0);
    record.writeUInt16BE(type, 2);
    record.writeUInt16BE(1, 4);
    record.writeUInt32BE(ttl, 6);
    record.writeUInt16BE(rdata.length, 10);
    return Buffer.concat([record, rdata]);
  });

  return Buffer.concat([header, query.subarray(12, questionEnd), ...records]);
}
