import test from "node:test";
import assert from "node:assert/strict";
import {
  matchesFilter,
  parseDisplayFilter,
  filterErrorOf,
  protocolHierarchy,
  endpointsOf,
  ioSeriesOf,
  conversationsOf,
} from "./index.ts";

const tcpRow = {
  source: "192.168.1.24",
  destination: "10.0.0.42",
  protocol: "TCP",
  length: 60,
  info: "49812 → 443 [SYN] Seq=0 Len=0",
  layers: [
    { label: "Ethernet II", value: "3c:22:fb:9a:11:02 → 3c:22:fb:9a:10:01" },
    { label: "Internet Protocol Version 4", value: "192.168.1.24 → 10.0.0.42" },
    { label: "ttl", value: "64" },
    { label: "source port", value: "49812" },
    { label: "destination port", value: "443" },
    { label: "flags", value: "SYN" },
  ],
};

const tlsRow = {
  source: "192.168.1.24",
  destination: "10.0.0.42",
  protocol: "TLS",
  length: 517,
  info: "49812 → 443 Client Hello (SNI: workbench.test)",
  layers: [
    { label: "Ethernet II", value: "3c:22:fb:9a:11:02 → 3c:22:fb:9a:10:01" },
    { label: "Internet Protocol Version 4", value: "192.168.1.24 → 10.0.0.42" },
    { label: "source port", value: "49812" },
    { label: "destination port", value: "443" },
    { label: "flags", value: "ACK" },
    { label: "TLS Server Name Indication", value: "workbench.test" },
  ],
};

const dnsRow = {
  source: "192.168.1.24",
  destination: "1.1.1.1",
  protocol: "DNS",
  length: 73,
  info: "Standard query 0x8f2a A workbench.test",
  layers: [
    { label: "Internet Protocol Version 4", value: "192.168.1.24 → 1.1.1.1" },
    { label: "source port", value: "51820" },
    { label: "destination port", value: "53" },
  ],
};

test("protocol names match protocol families, not exact display strings", () => {
  assert.equal(matchesFilter(tcpRow, "tcp"), true);
  assert.equal(matchesFilter(tlsRow, "tcp"), true); // TLS rides on TCP
  assert.equal(matchesFilter(dnsRow, "udp"), true); // DNS rides on UDP
  assert.equal(matchesFilter(dnsRow, "dns"), true);
  assert.equal(matchesFilter(dnsRow, "tcp"), false);
  assert.equal(matchesFilter(tlsRow, "tls"), true);
});

test("and/or/not and parentheses combine with precedence", () => {
  assert.equal(matchesFilter(tcpRow, "tcp and ip.src == 192.168.1.24"), true);
  assert.equal(matchesFilter(tcpRow, "dns or tcp"), true);
  assert.equal(matchesFilter(tcpRow, "not dns"), true);
  assert.equal(matchesFilter(tcpRow, "not tcp and not udp"), false);
  assert.equal(matchesFilter(tcpRow, "(dns or arp) and tcp"), false);
  assert.equal(matchesFilter(tcpRow, "(dns or tls) and ip.dst == 10.0.0.42"), false);
  assert.equal(matchesFilter(tlsRow, "(dns or tls) and ip.dst == 10.0.0.42"), true);
});

test("ordering operators and contains work on supported fields", () => {
  assert.equal(matchesFilter(tcpRow, "frame.len > 50"), true);
  assert.equal(matchesFilter(tcpRow, "frame.len < 50"), false);
  assert.equal(matchesFilter(tcpRow, "frame.len >= 60"), true);
  assert.equal(matchesFilter(tcpRow, "frame.len != 60"), false);
  assert.equal(matchesFilter(tcpRow, "info contains SYN"), true);
  assert.equal(matchesFilter(tlsRow, 'info contains "sni"'), true);
  assert.equal(matchesFilter(tcpRow, "ip.ttl == 64"), true);
  assert.equal(matchesFilter(tcpRow, "ip.ttl < 64"), false);
});

test("transport port fields distinguish tcp and udp families", () => {
  assert.equal(matchesFilter(tcpRow, "tcp.port == 443"), true);
  assert.equal(matchesFilter(tcpRow, "tcp.srcport == 49812"), true);
  assert.equal(matchesFilter(tcpRow, "tcp.dstport == 49812"), false);
  assert.equal(matchesFilter(tcpRow, "udp.port == 53"), false); // tcp-family row
  assert.equal(matchesFilter(dnsRow, "udp.port == 53"), true);
  assert.equal(matchesFilter(dnsRow, "tcp.port == 53"), false);
});

test("tcp flag booleans evaluate against the flags layer", () => {
  assert.equal(matchesFilter(tcpRow, "tcp.flags.syn == 1"), true);
  assert.equal(matchesFilter(tcpRow, "tcp.flags.ack == 1"), false);
  assert.equal(matchesFilter(tcpRow, "tcp.flags.syn == 0"), false);
  assert.equal(matchesFilter(tlsRow, "tcp.flags.syn == 0 and tcp.flags.ack == 1"), true);
});

test("eth and ip address fields parse from layer values", () => {
  assert.equal(matchesFilter(tcpRow, "eth.src == 3c:22:fb:9a:11:02"), true);
  assert.equal(matchesFilter(tcpRow, "eth.dst == 3c:22:fb:9a:11:02"), false);
  assert.equal(matchesFilter(tcpRow, "eth.addr == 3c:22:fb:9a:10:01"), true);
  assert.equal(matchesFilter(tcpRow, "ip.src == 192.168.1.24"), true);
  assert.equal(matchesFilter(tcpRow, "ip.dst == 192.168.1.24"), false);
});

test("syntax errors are positioned and specific", () => {
  assert.deepEqual(filterErrorOf("tcp && udp"), { message: 'unexpected character "&"', position: 4 });
  const unknown = filterErrorOf("tcp.port == 443 and bogusproto");
  assert.ok(unknown);
  assert.match(unknown.message, /neither a known protocol/);
  assert.equal(unknown.position, 20);
  const missing = filterErrorOf("tcp.port ==");
  assert.ok(missing);
  assert.match(missing.message, /missing a value/);
  const badValue = filterErrorOf("tcp.port == http");
  assert.ok(badValue);
  assert.match(badValue.message, /needs a number/);
  const unclosed = filterErrorOf("(tcp and udp");
  assert.ok(unclosed);
  assert.match(unclosed.message, /closing parenthesis/);
  assert.equal(filterErrorOf(""), null);
  assert.equal(filterErrorOf("tcp.port == 443"), null);
});

test("parse-once evaluate-many is reusable across rows", () => {
  const parsed = parseDisplayFilter("tcp.port == 443");
  assert.equal(parsed.ok, true);
  if (parsed.ok) {
    assert.equal(parsed.matches(tcpRow), true);
    assert.equal(parsed.matches(dnsRow), false);
  }
});

test("quoted values survive spaces for string fields", () => {
  assert.equal(matchesFilter(tlsRow, 'info contains "Client Hello"'), true);
  assert.equal(matchesFilter(tlsRow, "info contains \"client hello\""), true); // case-insensitive contains
});

// --- protocol hierarchy --------------------------------------------------------

const httpRow = {
  source: "192.168.1.24",
  destination: "10.0.0.80",
  protocol: "HTTP",
  length: 512,
  info: "GET /api/evidence HTTP/1.1",
  layers: [
    { label: "Ethernet II", value: "3c:22:fb:9a:11:02 → 3c:22:fb:9a:10:01" },
    { label: "Internet Protocol Version 4", value: "192.168.1.24 → 10.0.0.80" },
    { label: "source port", value: "49813" },
    { label: "destination port", value: "80" },
    { label: "HTTP/1.x start line", value: "GET /api/evidence HTTP/1.1" },
  ],
};

function findNodes(nodes, protocol, acc = []) {
  for (const n of nodes) {
    if (n.protocol === protocol) acc.push(n);
    findNodes(n.children, protocol, acc);
  }
  return acc;
}

test("protocol hierarchy counts protocol chains, not flat leaves", () => {
  const tree = protocolHierarchy([tcpRow, tlsRow, httpRow, dnsRow]);
  // eth-rooted chains (tcp/tls/http rows) and the dns row's direct ip root
  const ipNodes = findNodes(tree, "ip");
  assert.equal(ipNodes.length, 2);
  assert.equal(ipNodes.reduce((sum, n) => sum + n.packets, 0), 4); // every IPv4 row
  const eth = tree.find((n) => n.protocol === "eth");
  assert.ok(eth);
  assert.equal(eth.packets, 3);
  const tcp = findNodes(eth.children, "tcp");
  assert.equal(tcp.length, 1);
  assert.equal(tcp[0].packets, 3); // tcp + tls + http
  const http = findNodes(tcp[0].children, "http");
  assert.equal(http.length, 1);
  assert.equal(http[0].packets, 1);
  assert.equal(http[0].bytes, 512);
});

// --- endpoints ------------------------------------------------------------------

test("endpoints aggregate ip and mac families with packets and bytes", () => {
  const rows = endpointsOf([tcpRow, tlsRow]);
  const source = rows.find((r) => r.address === "192.168.1.24");
  assert.ok(source);
  assert.equal(source.family, "ip4");
  assert.equal(source.packets, 2);
  assert.equal(source.bytes, 577);
  const mac = rows.find((r) => r.address === "3c:22:fb:9a:11:02");
  assert.ok(mac);
  assert.equal(mac.family, "mac");
  assert.equal(mac.packets, 2);
});

// --- IO series -------------------------------------------------------------------

function timedRow(no, time_ms, length) {
  return { source: "a", destination: "b", protocol: "TCP", length, info: "x", time_ms, layers: [] };
}

test("io series buckets packets across the capture time span", () => {
  const rows = [
    timedRow(1, 0, 100),
    timedRow(2, 500, 200),
    timedRow(3, 1000, 300),
    timedRow(4, 1000, 300),
  ];
  const buckets = ioSeriesOf(rows, 4);
  assert.equal(buckets.length, 4);
  assert.equal(buckets[0].packets, 1);
  assert.equal(buckets[0].bytes, 100);
  assert.equal(buckets[3].packets, 2);
  assert.equal(buckets[3].bytes, 600);
  const empty = ioSeriesOf([]);
  assert.equal(empty.length, 0);
});

test("conversation sorting still prefers the busiest pair", () => {
  const pairs = conversationsOf([tcpRow, tlsRow, dnsRow]);
  assert.equal(pairs[0].packets, 2);
  assert.ok(pairs[0].endpoints.join(" ").includes("10.0.0.42"));
});
