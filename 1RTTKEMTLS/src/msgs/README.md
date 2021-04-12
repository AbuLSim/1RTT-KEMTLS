## codec.rs
introduces Reader struct with buffer and offset
the struct allows implementations of
  init: initializes Reader with some bytes
  rest: pauses the reader to continue later on
  take: returns a reader with sliced non read buff
  any_left: checks if entire buffer was read
  left: calculates how much left to be read
  used: returns offset
  sub:  substitutes the reader with ?????????

links Reader with Codec trait that contains
  encode: appends onto some bytes -- implementation depends on struct
  read: decodes by manipulating the Reader -- implementation depends on struct
  get_encoding: returns the result of encode function
  read_bytes: returns the bytes to be read as Reader struct

offers implementations of various Codec encode and read functions for
u8, u16, u24, u32, u64 structs. They encode 8, 16 , .., 64 bytes into Readers

offers implementations of encode and read functions for vectors
of type u8, u16, u24, u32, u64

## enums.rs
This crate is generated automatically, it  defines the enum values for
the entities below
All values are taken from the various RFCs covering TLS, and are listed by IANA.
The entities are:
  ProtocolVersion, HashAlgorithm, SignatureAlgorithm, ClientCertificateType,
  Compression, ContentType, HandshakeType, AlertLevel, AlertDescription,
  HeartbeatMessageType, ExtensionType, ServerNameType, NamedCurve, NamedGroup,
  CipherSuite, ECPointFormat, HeartbeatMode, ECCurveType, SignatureScheme,
  PSKKeyExchangeMode, KeyUpdateRequest, CertificateStatusType

## alerts.rs
introduces AlertMessagePayload struct with AlertLevel and AlertDescription
calls Codec from codec.rs the struct allows implementations of:
  encode: uses the encoding functions from enums crate
  read: returns some AlertMessagePayload after using read from enums crate
