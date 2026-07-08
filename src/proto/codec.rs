//! Bounds-checked byte reader/writer shared across the proto wire codecs.
//!
//! `Reader` fails a short read with `Error::MessageTooShort { expected, got }`
//! where `expected` is the cumulative byte offset it needed (`position + n`) and
//! `got` is the total buffer length — reproducing the codecs' existing per-field
//! and up-front length-check values exactly.
use crate::proto::Error;

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    #[allow(dead_code)]
    pub(crate) fn position(&self) -> usize {
        self.pos
    }
    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub(crate) fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
    /// Ensure at least `n` more bytes are available; else MessageTooShort.
    pub(crate) fn require(&self, n: usize) -> Result<(), Error> {
        if self.pos + n > self.buf.len() {
            return Err(Error::MessageTooShort {
                expected: self.pos + n,
                got: self.buf.len(),
            });
        }
        Ok(())
    }
    /// Advance the cursor by `n` (caller has already validated bounds, e.g. via a
    /// sub-decoder that returned a consumed count). Debug-panics if out of range.
    pub(crate) fn advance(&mut self, n: usize) {
        self.pos += n;
        debug_assert!(self.pos <= self.buf.len());
    }
    pub(crate) fn read_u8(&mut self) -> Result<u8, Error> {
        self.require(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }
    pub(crate) fn read_array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.require(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(a)
    }
    pub(crate) fn read_u16_le(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.read_array::<2>()?))
    }
    #[allow(dead_code)]
    pub(crate) fn read_u32_le(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }
    pub(crate) fn read_u64_le(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }
    pub(crate) fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        self.require(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

pub(crate) struct Writer {
    buf: alloc::vec::Vec<u8>,
}
impl Writer {
    pub(crate) fn new() -> Self {
        Self {
            buf: alloc::vec::Vec::new(),
        }
    }
    pub(crate) fn with_capacity(n: usize) -> Self {
        Self {
            buf: alloc::vec::Vec::with_capacity(n),
        }
    }
    pub(crate) fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub(crate) fn write_u16_le(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    #[allow(dead_code)]
    pub(crate) fn write_u32_le(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub(crate) fn write_u64_le(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub(crate) fn write_bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }
    pub(crate) fn into_vec(self) -> alloc::vec::Vec<u8> {
        self.buf
    }
}
