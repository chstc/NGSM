//! Snapshot-bounded reads shared by application tails and both event readers.

use std::io::{Read, Seek, SeekFrom};

pub struct Tail {
    pub bytes: Vec<u8>,
    pub partial: bool,
}

pub fn read_tail(
    reader: &mut (impl Read + Seek),
    snapshot_len: u64,
    budget: u64,
    utf16: bool,
) -> std::io::Result<Tail> {
    let mut start = snapshot_len.saturating_sub(budget);
    if utf16 && !start.is_multiple_of(2) {
        start += 1;
    }
    reader.seek(SeekFrom::Start(start))?;
    let count = snapshot_len.saturating_sub(start).min(budget);
    let mut bytes = Vec::new();
    reader.take(count).read_to_end(&mut bytes)?;
    Ok(Tail {
        bytes,
        partial: start > 0,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Cursor;

    /// Keeps appending forever, even when the caller captured a shorter length.
    #[derive(Default)]
    pub struct GrowingReader {
        pub read: u64,
        pub position: u64,
    }

    impl Read for GrowingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            buf.fill(b'x');
            self.read += buf.len() as u64;
            self.position += buf.len() as u64;
            Ok(buf.len())
        }
    }

    impl Seek for GrowingReader {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            let SeekFrom::Start(pos) = pos else {
                return Err(std::io::Error::other("absolute seek required"));
            };
            self.position = pos;
            Ok(pos)
        }
    }

    #[test]
    fn captured_length_not_eof_limits_an_infinite_growing_reader() {
        for (len, budget, expected) in [(0, 64, 0), (5, 64, 5), (1024, 64, 64)] {
            let mut reader = GrowingReader::default();
            let tail = read_tail(&mut reader, len, budget, false).unwrap();
            assert_eq!(reader.read, expected);
            assert_eq!(tail.bytes.len() as u64, expected);
        }
    }

    #[test]
    fn truncated_or_rotated_snapshots_finish_at_actual_eof() {
        for len in [5, 30, 1000] {
            let mut reader = Cursor::new(b"short");
            let tail = read_tail(&mut reader, len, 64, false).unwrap();
            assert_eq!(
                tail.bytes,
                if len <= 64 { b"short".as_slice() } else { &[] }
            );
        }
    }

    #[test]
    fn utf16_start_is_aligned_without_exceeding_the_snapshot() {
        let mut reader = GrowingReader::default();
        let tail = read_tail(&mut reader, 101, 64, true).unwrap();
        assert_eq!(tail.bytes.len(), 63);
        assert_eq!(reader.position, 101);
        assert!(tail.partial);
    }
}
