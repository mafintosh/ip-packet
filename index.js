const ipv4 = {
  preencode (state, ip) {
    state.end += 4
  },
  encode (state, ip) {
    for (let i = 0; i < 4; i++) {
      const oct = parseInt(ip, 10)
      state.buffer[state.start++] = oct
      ip = ip.slice(oct < 100 ? oct < 10 ? 2 : 3 : 4)
    }
  },
  decode (state) {
    return state.buffer[state.start++] + '.' + state.buffer[state.start++] + '.' + state.buffer[state.start++] + '.' + state.buffer[state.start++]
  }
}

const uint16be = {
  preencode (state, n) {
    state.end += 2
  },
  encode (state, n) {
    state.buffer[state.start++] = n >>> 8
    state.buffer[state.start++] = n & 255
  },
  decode (state) {
    return 256 * state.buffer[state.start++] + state.buffer[state.start++]
  }
}

exports.addresses = function (state) {
  state.start += 2
  const length = uint16be.decode(state)
  state.start += 8
  const src = ipv4.decode(state)
  const dest = ipv4.decode(state)
  state.start += length - 20
  return [src, dest]
}

exports.checksum = checksum

exports.preencode = function (state, packet) {
  state.end += 20 + packet.data.byteLength
}

exports.encode = function (state, packet) {
  state.buffer[state.start++] = packet.version << 4 | (packet.ihl || 5)
  state.buffer[state.start++] = (packet.dscp || 0) << 2 | (packet.ecn || 0)
  uint16be.encode(state, 20 + packet.data.byteLength)
  uint16be.encode(state, packet.identification || 0)
  uint16be.encode(state, (packet.flags || 0) << 13 | (packet.fragmentOffset || 0))
  state.buffer[state.start++] = packet.ttl || 0
  state.buffer[state.start++] = packet.protocol || 0
  uint16be.encode(state, packet.checksum || 0)
  ipv4.encode(state, packet.sourceIp)
  ipv4.encode(state, packet.destinationIp)
  packet.data.copy(state.buffer, state.start)
  state.start += packet.data.byteLength
}

exports.decode = function (state) {
  let n = state.buffer[state.start++]

  const version = n >> 4
  if (version !== 4) throw new Error('Currently only IPv4 is supported')
  const ihl = n & 15
  if (ihl > 5) throw new Error('Currently only IHL <= 5 is supported')

  n = state.buffer[state.start++]
  const dscp = n >> 2
  const ecn = n & 3

  const length = uint16be.decode(state)
  const identification = uint16be.decode(state)

  n = uint16be.decode(state)
  const flags = n >> 13
  const fragmentOffset = n & 8191

  const ttl = state.buffer[state.start++]
  const protocol = state.buffer[state.start++]
  const checksum = uint16be.decode(state)

  const sourceIp = ipv4.decode(state)
  const destinationIp = ipv4.decode(state)

  const data = state.buffer.subarray(state.start, state.start += (length - 20))

  return {
    version,
    ihl,
    dscp,
    ecn,
    length,
    identification,
    flags,
    fragmentOffset,
    ttl,
    protocol,
    sourceIp,
    destinationIp,
    checksum,
    data
  }
}

function checksum (packet) {
  const state = { buffer: packet, start: 0, end: 20 }

  let sum = 0
  while (state.start < state.end) {
    if (state.start === 10) state.start += 2
    else sum += uint16be.decode(state)
  }

  while (true) {
    const carry = sum >> 16
    if (!carry) break
    sum = (sum & 0xffff) + carry
  }

  return ~sum & 0xffff
}
