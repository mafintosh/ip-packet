const test = require('brittle')
const c = require('compact-encoding')
const ip = require('./')

const FIXTURE = Buffer.from('4500004000004000400626510a16001e0a16001efb311f900a7fd88600000000b0c2ffff97830000020404ec010303060101080a9158fbf80000000004020000', 'hex')

test('test tcp packet', function (t) {
  const packet = c.decode(ip, FIXTURE)

  t.is(packet.sourceIp, '10.22.0.30')
  t.is(packet.destinationIp, '10.22.0.30')
  t.alike(ip.addresses({ start: 0, end: FIXTURE.byteLength, buffer: FIXTURE }), ['10.22.0.30', '10.22.0.30'])

  const buffer = c.encode(ip, packet)

  t.alike(buffer, FIXTURE)
})
