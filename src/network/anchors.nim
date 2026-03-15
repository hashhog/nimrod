## Anchor connections persistence for eclipse attack protection
## Persists 2 block-relay-only peer addresses to anchors.dat
## On restart, reconnect to these anchors first
##
## Reference: Bitcoin Core net.cpp ANCHORS_DATABASE_FILENAME
## Reference: Bitcoin Core addrdb.cpp ReadAnchors/DumpAnchors

import std/[os, times, options, strutils]
import chronicles
import ../primitives/serialize
import ./netgroup

const
  MaxBlockRelayOnlyAnchors* = 2
  AnchorsFileName* = "anchors.dat"
  AnchorsMagic* = [0x61'u8, 0x6e, 0x63, 0x68]  # "anch"
  AnchorsVersion* = 1'u8

type
  AnchorAddress* = object
    ## Persisted anchor peer address
    services*: uint64
    ip*: array[16, byte]
    port*: uint16
    timestamp*: int64  # Unix timestamp when added

  AnchorList* = ref object
    anchors*: seq[AnchorAddress]
    dataDir*: string
    isDirty*: bool

proc anchorsPath*(al: AnchorList): string =
  al.dataDir / AnchorsFileName

proc newAnchorList*(dataDir: string = "."): AnchorList =
  AnchorList(
    anchors: @[],
    dataDir: dataDir,
    isDirty: false
  )

proc serialize*(anchor: AnchorAddress): seq[byte] =
  var w = BinaryWriter()
  w.writeUint64LE(anchor.services)
  for b in anchor.ip:
    w.writeUint8(b)
  w.writeUint16LE(anchor.port)
  w.writeInt64LE(anchor.timestamp)
  result = w.data

proc deserializeAnchor*(r: var BinaryReader): AnchorAddress =
  result.services = r.readUint64LE()
  for i in 0 ..< 16:
    result.ip[i] = r.readUint8()
  result.port = r.readUint16LE()
  result.timestamp = r.readInt64LE()

proc save*(al: AnchorList) =
  ## Save anchor list to disk
  ## Format: magic (4) | version (1) | count (varint) | anchors...
  if not al.isDirty and fileExists(al.anchorsPath()):
    return

  # Limit to max anchors
  var toSave = al.anchors
  if toSave.len > MaxBlockRelayOnlyAnchors:
    toSave = toSave[0 ..< MaxBlockRelayOnlyAnchors]

  var w = BinaryWriter()

  # Magic
  for b in AnchorsMagic:
    w.writeUint8(b)

  # Version
  w.writeUint8(AnchorsVersion)

  # Count
  w.writeCompactSize(uint64(toSave.len))

  # Anchors
  for anchor in toSave:
    let anchorData = serialize(anchor)
    for b in anchorData:
      w.writeUint8(b)

  try:
    if not dirExists(al.dataDir):
      createDir(al.dataDir)
    writeFile(al.anchorsPath(), cast[string](w.data))
    al.isDirty = false
    info "saved anchor connections", count = toSave.len, path = al.anchorsPath()
  except CatchableError as e:
    error "failed to save anchor connections", error = e.msg

proc load*(al: AnchorList): bool =
  ## Load anchor list from disk
  ## Returns true if successfully loaded
  let path = al.anchorsPath()
  if not fileExists(path):
    debug "no anchors file found", path = path
    return false

  try:
    let content = readFile(path)
    if content.len < 6:  # minimum: magic(4) + version(1) + count(1)
      warn "anchors file too small", size = content.len
      return false

    var data: seq[byte]
    for c in content:
      data.add(byte(c))

    var r = BinaryReader(data: data, pos: 0)

    # Verify magic
    var magic: array[4, byte]
    for i in 0 ..< 4:
      magic[i] = r.readUint8()
    if magic != AnchorsMagic:
      warn "invalid anchors file magic"
      return false

    # Version
    let version = r.readUint8()
    if version != AnchorsVersion:
      warn "unsupported anchors version", version = version
      return false

    # Count
    let count = r.readCompactSize()
    if count > uint64(MaxBlockRelayOnlyAnchors * 2):  # sanity check
      warn "too many anchors in file", count = count
      return false

    # Read anchors
    al.anchors = @[]
    for i in 0 ..< int(count):
      let anchor = r.deserializeAnchor()
      al.anchors.add(anchor)

    # Limit to max
    if al.anchors.len > MaxBlockRelayOnlyAnchors:
      al.anchors = al.anchors[0 ..< MaxBlockRelayOnlyAnchors]

    info "loaded anchor connections", count = al.anchors.len, path = path
    return true

  except CatchableError as e:
    error "failed to load anchors", error = e.msg
    return false

proc add*(al: AnchorList, services: uint64, ip: array[16, byte], port: uint16) =
  ## Add an anchor address
  let anchor = AnchorAddress(
    services: services,
    ip: ip,
    port: port,
    timestamp: getTime().toUnix()
  )

  # Check for duplicates
  for existing in al.anchors:
    if existing.ip == ip and existing.port == port:
      return  # Already exists

  al.anchors.add(anchor)

  # Limit size
  if al.anchors.len > MaxBlockRelayOnlyAnchors:
    # Keep most recent
    al.anchors = al.anchors[^MaxBlockRelayOnlyAnchors .. ^1]

  al.isDirty = true

proc addFromString*(al: AnchorList, address: string, port: uint16, services: uint64 = 1) =
  ## Add anchor from address string
  ## Converts IPv4 to IPv4-mapped IPv6
  let ip = parseIpAddr(address)
  var ipBytes: array[16, byte]

  if ip.isV6:
    ipBytes = ip.v6
  else:
    # Convert IPv4 to IPv4-mapped IPv6
    for i in 0 ..< 10:
      ipBytes[i] = 0
    ipBytes[10] = 0xFF
    ipBytes[11] = 0xFF
    ipBytes[12] = ip.v4[0]
    ipBytes[13] = ip.v4[1]
    ipBytes[14] = ip.v4[2]
    ipBytes[15] = ip.v4[3]

  al.add(services, ipBytes, port)

proc pop*(al: AnchorList): Option[AnchorAddress] =
  ## Pop and return the last anchor address
  if al.anchors.len == 0:
    return none(AnchorAddress)

  result = some(al.anchors[^1])
  al.anchors.delete(al.anchors.len - 1)
  al.isDirty = true

proc clear*(al: AnchorList) =
  ## Clear all anchors
  if al.anchors.len > 0:
    al.anchors = @[]
    al.isDirty = true

proc count*(al: AnchorList): int =
  al.anchors.len

proc isEmpty*(al: AnchorList): bool =
  al.anchors.len == 0

proc ipToString*(ip: array[16, byte]): string =
  ## Convert IP bytes to string representation
  # Check for IPv4-mapped
  var isV4Mapped = true
  for i in 0 ..< 10:
    if ip[i] != 0:
      isV4Mapped = false
      break
  if isV4Mapped and ip[10] == 0xFF and ip[11] == 0xFF:
    # IPv4
    return $ip[12] & "." & $ip[13] & "." & $ip[14] & "." & $ip[15]
  else:
    # IPv6
    result = ""
    for i in 0 ..< 8:
      if i > 0: result.add(":")
      let val = (uint16(ip[i * 2]) shl 8) or uint16(ip[i * 2 + 1])
      result.add(val.toHex(4).toLowerAscii())

proc getCurrentBlockRelayOnlyAddresses*(addresses: seq[(string, uint16, uint64)]): seq[AnchorAddress] =
  ## Convert current block-relay-only connections to anchor addresses
  ## Input: seq of (address, port, services)
  result = @[]
  for (address, port, services) in addresses:
    let ip = parseIpAddr(address)
    var ipBytes: array[16, byte]

    if ip.isV6:
      ipBytes = ip.v6
    else:
      for i in 0 ..< 10:
        ipBytes[i] = 0
      ipBytes[10] = 0xFF
      ipBytes[11] = 0xFF
      ipBytes[12] = ip.v4[0]
      ipBytes[13] = ip.v4[1]
      ipBytes[14] = ip.v4[2]
      ipBytes[15] = ip.v4[3]

    result.add(AnchorAddress(
      services: services,
      ip: ipBytes,
      port: port,
      timestamp: getTime().toUnix()
    ))

  # Limit to max
  if result.len > MaxBlockRelayOnlyAnchors:
    result = result[0 ..< MaxBlockRelayOnlyAnchors]

proc delete*(al: AnchorList) =
  ## Delete the anchors file from disk (for testing/cleanup)
  let path = al.anchorsPath()
  if fileExists(path):
    try:
      removeFile(path)
      debug "deleted anchors file", path = path
    except CatchableError as e:
      error "failed to delete anchors file", error = e.msg
  al.anchors = @[]
  al.isDirty = false
