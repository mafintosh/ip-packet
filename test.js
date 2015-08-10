var tape = require('tape')
var ip = require('./')

tape('encode + decode', function (t) {
  var packet = {
    version: 4,
    protocol: 0,
    sourceIp: '127.0.0.1',
    destinationIp: '127.0.0.1',
    data: new Buffer('lol')
  }

  var buf = ip.encode(packet)

  t.same(ip.encodingLength(packet), buf.length)

  var decoded = ip.decode(buf)

  t.same(decoded.version, packet.version)
  t.same(decoded.protocol, packet.protocol)
  t.same(decoded.sourceIp, packet.sourceIp)
  t.same(decoded.destinationIp, packet.destinationIp)
  t.same(decoded.data, packet.data)
  t.same(ip.encode.bytes, buf.length)
  t.same(ip.decode.bytes, buf.length)

  t.end()
})

tape('decode bad checksum', function (t) {
  var packet = {
    version: 4,
    protocol: 0,
    sourceIp: '127.0.0.1',
    destinationIp: '127.0.0.1',
    data: new Buffer('lol')
  }

  var buf = ip.encode(packet)
  buf[4] = 42

  t.throws(function () {
    ip.decode(buf)
  })

  t.end()
})
