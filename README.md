# ip-packet

Encode/decode raw ip packets

```
npm install ip-packet
```

## Usage

``` js
// compact-encoder
const ip = require('ip-packet')

ip.encode(state, { version, ... })
console.log(ip.decode(state))
```

## API

#### `ip.encode(state, packet)`

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
  checksum: 0,
  sourceIp: '127.0.0.1',
  destinationIp: '127.0.0.1',
  data: <Buffer>
}
```

#### `packet = ip.decode(state)

Decode a packet.

#### `ip.preencode(state, packet)`

Preencode a packet.

## License

Apache-2.0
