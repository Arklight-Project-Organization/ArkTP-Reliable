use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

// 加密相关

// 后量子密码学

// 性能优化
use rayon::prelude::*;


// ==================== 序列号包装器 ====================
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SeqNum(pub u32);

impl SeqNum {
    pub fn new(value: u32) -> Self {
        Self(value)
    }
    
    #[inline]
    pub fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
    
    #[inline]
    pub fn add(self, n: u32) -> Self {
        Self(self.0.wrapping_add(n))
    }
    
    #[inline]
    pub fn sub(self, n: u32) -> Self {
        Self(self.0.wrapping_sub(n))
    }
    
    #[inline]
    pub fn is_before(self, other: SeqNum) -> bool {
        self.0.wrapping_sub(other.0) > u32::MAX / 2
    }
    
    #[inline]
    pub fn is_after(self, other: SeqNum) -> bool {
        other.is_before(self)
    }
    
    #[inline]
    pub fn diff(self, other: SeqNum) -> i64 {
        let d = self.0.wrapping_sub(other.0);
        if d > u32::MAX / 2 {
            -(d.wrapping_neg() as i64)
        } else {
            d as i64
        }
    }
    
    #[inline]
    pub fn in_window(self, base: SeqNum, window: u32) -> bool {
        let diff = self.diff(base);
        diff >= 0 && diff < window as i64
    }
}

impl std::fmt::Display for SeqNum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for SeqNum {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

impl From<SeqNum> for u32 {
    fn from(s: SeqNum) -> Self {
        s.0
    }
}

// ==================== 窗口过滤器 ====================
#[derive(Clone)]
pub struct WindowedFilter {
    samples: VecDeque<(Instant, f64)>,
    window: Duration,
    sum: f64,
}

impl WindowedFilter {
    pub fn new(window: Duration) -> Self {
        Self {
            samples: VecDeque::with_capacity(64),
            window,
            sum: 0.0,
        }
    }
    
    #[inline]
    pub fn update(&mut self, now: Instant, sample: f64) {
        while let Some((t, v)) = self.samples.front() {
            if now.duration_since(*t) > self.window {
                self.sum -= *v;
                self.samples.pop_front();
            } else {
                break;
            }
        }
        
        self.samples.push_back((now, sample));
        self.sum += sample;
    }
    
    #[inline]
    pub fn max(&self) -> f64 {
        self.samples.iter().map(|(_, v)| *v).fold(f64::MIN, f64::max)
    }
    
    #[inline]
    pub fn min(&self) -> f64 {
        self.samples.iter().map(|(_, v)| *v).fold(f64::MAX, f64::min)
    }
    
    #[inline]
    pub fn avg(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        self.sum / self.samples.len() as f64
    }
    
    #[inline]
    pub fn len(&self) -> usize {
        self.samples.len()
    }
    
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
}

