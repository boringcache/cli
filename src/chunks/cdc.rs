use super::ChunkingParams;

const WINDOW_SIZE: usize = 64;
const WINDOW_MASK: usize = WINDOW_SIZE - 1;

pub struct CdcState {
    params: ChunkingParams,
    mask: u64,
    hash: u64,
    length: usize,
    window: [u8; WINDOW_SIZE],
    window_pos: usize,
}

impl CdcState {
    pub fn new(params: ChunkingParams) -> Self {
        Self {
            params,
            mask: mask_for_size(params.avg_size),
            hash: 0,
            length: 0,
            window: [0u8; WINDOW_SIZE],
            window_pos: 0,
        }
    }

    /// Feed a byte into the rolling hash; returns true if a cut-point is detected.
    pub fn update(&mut self, byte: u8) -> bool {
        let outgoing = self.window[self.window_pos];
        if outgoing != 0 {
            self.hash ^= gear_value(outgoing);
        }

        self.window[self.window_pos] = byte;
        self.window_pos = (self.window_pos + 1) & WINDOW_MASK;

        if byte != 0 {
            self.hash = ((self.hash << 1) ^ gear_value(byte)).wrapping_mul(0x45d9f3b);
        } else {
            self.hash = (self.hash << 1) ^ 0xa3761b1d;
        }

        self.length += 1;

        if self.length < self.params.min_size {
            return false;
        }

        (self.hash & self.mask) == 0
    }

    #[inline]
    pub fn should_force(&self) -> bool {
        self.length >= self.params.max_size
    }

    pub fn reset(&mut self) {
        self.hash = 0;
        self.length = 0;
        self.window.fill(0);
        self.window_pos = 0;
    }
}

fn mask_for_size(avg_size: usize) -> u64 {
    let mut bits = avg_size.trailing_zeros() as i32;
    if bits <= 0 {
        bits = 1;
    } else if bits >= 62 {
        bits = 62;
    }
    (1u64 << bits) - 1
}

#[inline]
fn gear_value(byte: u8) -> u64 {
    if byte == 0 {
        return 0;
    }

    let x = byte as u64;
    let mut v = x.wrapping_mul(0x9e3779b185ebca87);
    v ^= v >> 33;
    v = v.wrapping_mul(0xc2b2ae3d27d4eb4f);
    v ^= v >> 29;
    v = v.wrapping_mul(0x165667b19e3779f9);
    v ^= v >> 32;
    v
}
