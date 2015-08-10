# ip-packet

Encode/decode raw ip packets

```
npm install ip-packet
```

[![build status](http://img.shields.io/travis/mafintosh/ip-packet.svg?style=flat)](http://travis-ci.org/mafintosh/ip-packet)

## Usage

``` js
var ip = require('ip-packet')

var buf = ip.encode({
  version: 4,
  protocol: 0,
  sourceIp: '127.0.0.1',
  destinationIp: '127.0.0.1',
  data: new Buffer('some data')
})

console.log(ip.decode(buf)) // prints out the decoded packet
```

## API

#### `buffer = ip.encode(packet, [buffer], [offset])`

Encode a packet. A packet should look like this

``` js
{
  version: 4,
  dscp: 0,
  ecn: 0,
  identification: 0,
  flags: 0,
  fragmentOffset: 0,
  ttl: 0,
  protocol: 0,
  sourceIp: '127.0.0.1',
  destinationIp: '127.0.0.1',
  data: <Buffer>
}
```

#### `packet = ip.decode(buffer, [offset])`

Decode a packet. Throws an exception if the packet contains a bad checksum

#### `length = ip.encodingLength(packet)`

Returns the byte length of the packet encoded

## License

MIT
