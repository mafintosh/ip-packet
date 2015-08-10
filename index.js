exports.encode = encode
exports.decode = decode
exports.encodingLength = encodingLength
decode.bytes = encode.bytes = 0

function encode (packet, buf, offset) {
  if (!buf) buf = new Buffer(exports.encodingLength(packet))
  if (!offset) offset = 0

  buf[offset] = packet.version << 4 | (packet.ihl || 5)
  buf[offset + 1] = (packet.dscp || 0) << 2 | (packet.ecn || 0)
  buf.writeUInt16BE(20 + packet.data.length, offset + 2)
  buf.writeUInt16BE(packet.identification || 0, offset + 4)
  buf.writeUInt16BE((packet.flags || 0) << 13 | (packet.fragmentOffset || 0), offset + 6)
  buf[offset + 8] = packet.ttl || 0
  buf[offset + 9] = packet.protocol || 0
  buf.writeUInt16BE(0, offset + 10)
  encodeIp(packet.sourceIp, buf, offset + 12)
  encodeIp(packet.destinationIp, buf, offset + 16)
  buf.writeUInt16BE(checksum(buf, offset, offset + 20), offset + 10)
  packet.data.copy(buf, offset + 20)

  encode.bytes = 20 + packet.data.length

  return buf
}

function encodingLength (packet) {
  return 20 + packet.data.length
}

function decode (buf, offset) {
  if (!offset) offset = 0

  var version = buf[offset] >> 4
  if (version !== 4) throw new Error('Currently only IPv4 is supported')
  var ihl = buf[offset] & 15
  if (ihl > 5) throw new Error('Currently only IHL <= 5 is supported')
  var length = buf.readUInt16BE(offset + 2)
  var sum = checksum(buf, offset, offset + 20)

  if (sum) throw new Error('Bad checksum (' + sum + ')')

  exports.decode.bytes = length
  return {
    version: version,
    ihl: ihl,
    dscp: buf[offset + 1] >> 2,
    ecn: buf[offset + 1] & 3,
    length: length,
    identification: buf.readUInt16BE(offset + 4),
    flags: buf[offset + 6] >> 5,
    fragmentOffset: buf.readUInt16BE(offset + 6) & 8191,
    ttl: buf[offset + 8],
    protocol: buf[offset + 9],
    checksum: buf.readUInt16BE(offset + 10),
    sourceIp: decodeIp(buf, offset + 12),
    destinationIp: decodeIp(buf, offset + 16),
    data: buf.slice(offset + 20, offset + length)
  }
}

function encodeIp (addr, buf, offset) {
  for (var i = 0; i < 4; i++) {
    var oct = parseInt(addr, 10)
    buf[offset++] = oct
    addr = addr.slice(oct < 100 ? oct < 10 ? 2 : 3 : 4)
  }
}

function decodeIp (buf, offset) {
  return buf[offset] + '.' + buf[offset + 1] + '.' + buf[offset + 2] + '.' + buf[offset + 3]
}

function checksum (buf, offset, end) {
  var sum = 0
  for (; offset < end; offset += 2) sum += buf.readUInt16BE(offset)
  while (true) {
    var carry = sum >> 16
    if (!carry) break
    sum = (sum & 0xffff) + carry
  }
  return ~sum & 0xffff
}
