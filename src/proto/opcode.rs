//! Opcodes and close codes, RFC 6455 §5.2 and §7.4.

/// What a frame carries.
///
/// The wire value is four bits. Everything not listed here is reserved, and a
/// reserved opcode is a protocol error rather than something to skip: §5.2 says
/// the receiver *must* fail the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpCode {
    /// A continuation of the fragmented message already in progress.
    Continuation,
    /// UTF-8 text. Validity is enforced, not assumed.
    Text,
    /// Opaque bytes.
    Binary,
    /// Start of the closing handshake.
    Close,
    /// Liveness probe.
    Ping,
    /// Reply to a probe.
    Pong,
}

impl OpCode {
    /// Decode the low four bits of the first header byte.
    ///
    /// Returns `None` for the reserved ranges (3-7 non-control, 11-15 control),
    /// which the caller turns into a protocol error.
    #[inline]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xA => Some(Self::Pong),
            _ => None,
        }
    }

    /// The four bits this opcode occupies on the wire.
    #[inline]
    pub const fn to_bits(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
        }
    }

    /// Whether this is a control frame.
    ///
    /// Control frames may be injected between the fragments of a data message,
    /// so this is what decides whether an arriving frame interrupts reassembly
    /// or continues it.
    #[inline]
    pub const fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

/// Why a connection closed, RFC 6455 §7.4.1.
///
/// Kept as a `u16` rather than a closed enum: the registry is extensible and
/// applications own 4000-4999, so refusing to represent an unknown code would
/// lose information the peer deliberately sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CloseCode(pub u16);

impl CloseCode {
    /// Normal closure, the purpose was fulfilled.
    pub const NORMAL: Self = Self(1000);
    /// The endpoint is going away (server shutting down, browser navigating).
    pub const AWAY: Self = Self(1001);
    /// A protocol error was detected.
    pub const PROTOCOL: Self = Self(1002);
    /// A frame of a type the endpoint cannot accept.
    pub const UNSUPPORTED: Self = Self(1003);
    /// Payload that should have been UTF-8 was not.
    pub const INVALID_PAYLOAD: Self = Self(1007);
    /// A message violated policy.
    pub const POLICY: Self = Self(1008);
    /// A message was too large to process.
    pub const TOO_LARGE: Self = Self(1009);
    /// Unexpected condition on the server.
    pub const INTERNAL_ERROR: Self = Self(1011);

    /// Whether this code may legally appear in a Close frame on the wire.
    ///
    /// 1005/1006/1015 are status codes the *application* may observe but which
    /// must never be sent, and the 0-999 range is unassigned. Sending one of
    /// those back is itself a protocol violation, so this is checked on both
    /// the decode and encode paths.
    #[inline]
    pub const fn is_sendable(self) -> bool {
        match self.0 {
            1000..=1003 | 1007..=1011 => true,
            1004..=1006 | 1012..=1014 => false,
            1015 => false,
            3000..=4999 => true,
            _ => false,
        }
    }
}

impl From<u16> for CloseCode {
    #[inline]
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<CloseCode> for u16 {
    #[inline]
    fn from(value: CloseCode) -> Self {
        value.0
    }
}
