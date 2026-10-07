use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

// 加密相关
use chacha20poly1305::aead::KeyInit;
use sha2::Digest;

// 后量子密码学

// 性能优化
use rayon::prelude::*;

use crate::*;

// ==================== 拥塞控制接口 ====================
pub trait CongestionControl: Send + Sync {
    fn on_packet_sent(&mut self, now: Instant, bytes_sent: u64);
    fn on_ack(&mut self, now: Instant, bytes_acked: u64, rtt: Option<Duration>);
    fn on_loss(&mut self, now: Instant);
    fn on_timeout(&mut self, now: Instant);
    fn on_duplicate_ack(&mut self, now: Instant);
    fn cwnd(&self) -> f64;
    fn ssthresh(&self) -> u32;
    fn can_send(&self, in_flight: u32, mtu: u16) -> bool;
    fn pacing_rate(&self) -> f64;
    fn pacing_rate_bytes(&self, mtu: u16) -> f64 { self.pacing_rate() * mtu as f64 }
    fn rto(&self) -> Duration;
    fn clone_box(&self) -> Box<dyn CongestionControl>;
}

impl Clone for Box<dyn CongestionControl> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

// ==================== Reno拥塞控制 ====================
#[derive(Clone)]
pub struct RenoCongestion {
    cwnd: f64,
    ssthresh: u32,
    rtt_srtt: f64,
    rtt_rttvar: f64,
    rtt_initialized: bool,
    dup_ack_count: u32,
    last_congestion_event: Option<Instant>,
}

impl RenoCongestion {
    pub fn new() -> Self {
        Self {
            cwnd: 8.0,
            ssthresh: 256,
            rtt_srtt: 0.0,
            rtt_rttvar: 0.0,
            rtt_initialized: false,
            dup_ack_count: 0,
            last_congestion_event: None,
        }
    }
}

impl CongestionControl for RenoCongestion {
    fn on_packet_sent(&mut self, _now: Instant, _bytes_sent: u64) {}

    fn on_ack(&mut self, now: Instant, bytes_acked: u64, rtt: Option<Duration>) {
        if let Some(rtt) = rtt {
            let rtt_ms = rtt.as_secs_f64() * 1000.0;
            if !self.rtt_initialized {
                self.rtt_srtt = rtt_ms;
                self.rtt_rttvar = rtt_ms / 2.0;
                self.rtt_initialized = true;
            } else {
                self.rtt_rttvar = 0.75 * self.rtt_rttvar + 0.25 * (self.rtt_srtt - rtt_ms).abs();
                self.rtt_srtt = 0.875 * self.rtt_srtt + 0.125 * rtt_ms;
            }
        }
        
        if let Some(last_event) = self.last_congestion_event {
            if now.duration_since(last_event) < Duration::from_secs(1) {
                self.cwnd += bytes_acked as f64 / self.cwnd * 0.5;
            } else {
                self.last_congestion_event = None;
            }
        } else {
            if self.cwnd < self.ssthresh as f64 {
                self.cwnd += bytes_acked as f64 / self.cwnd * 2.0;
            } else {
                self.cwnd += bytes_acked as f64 / self.cwnd / self.cwnd;
            }
        }
        
        self.cwnd = self.cwnd.min(65535.0);
        self.dup_ack_count = 0;
    }

    fn on_loss(&mut self, now: Instant) {
        self.ssthresh = (self.cwnd / 2.0) as u32;
        self.ssthresh = self.ssthresh.max(4);
        self.cwnd = 2.0;
        self.dup_ack_count = 0;
        self.last_congestion_event = Some(now);
    }

    fn on_timeout(&mut self, now: Instant) {
        self.on_loss(now);
    }
    
    fn on_duplicate_ack(&mut self, now: Instant) {
        self.dup_ack_count += 1;
        if self.dup_ack_count >= FAST_RETRANSMIT_THRESHOLD {
            self.ssthresh = (self.cwnd / 2.0) as u32;
            self.ssthresh = self.ssthresh.max(4);
            self.cwnd = self.ssthresh as f64 + FAST_RETRANSMIT_THRESHOLD as f64;
            self.dup_ack_count = 0;
            self.last_congestion_event = Some(now);
        }
    }

    fn cwnd(&self) -> f64 {
        self.cwnd
    }

    fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    fn can_send(&self, in_flight: u32, mtu: u16) -> bool {
        (self.cwnd * mtu as f64) > in_flight as f64
    }

    fn pacing_rate(&self) -> f64 {
        if self.rtt_initialized {
            self.cwnd / (self.rtt_srtt / 1000.0).max(0.001)
        } else {
            self.cwnd / 0.05
        }
    }

    fn rto(&self) -> Duration {
        if self.rtt_initialized {
            let rto = self.rtt_srtt + 4.0 * self.rtt_rttvar;
            Duration::from_millis(rto.max(MIN_RTO_MS as f64).min(MAX_RTO_MS as f64) as u64)
        } else {
            Duration::from_millis(200)
        }
    }

    fn clone_box(&self) -> Box<dyn CongestionControl> {
        Box::new(self.clone())
    }
}

// ==================== BBR拥塞控制 ====================
#[derive(Clone)]
pub struct BbrCongestion {
    state: BbrState,
    cwnd: f64,
    ssthresh: u32,
    rtt_srtt: f64,
    rtt_rttvar: f64,
    rtt_initialized: bool,
    bw_filter: WindowedFilter,
    rt_prop_filter: WindowedFilter,
    max_bw: f64,
    min_rtt: Duration,
    pacing_gain: f64,
    cwnd_gain: f64,
    inflight: f64,
    cycle_count: u32,
    last_cycle_start: Instant,
    probe_rtt_phase: ProbeRttPhase,
    packet_conservation: bool,
    dup_ack_count: u32,
    loss_events: VecDeque<Instant>,
}

#[derive(Clone, PartialEq)]
pub enum BbrState {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

#[derive(Clone, PartialEq)]
pub enum ProbeRttPhase {
    Enter,
    Wait,
    Exit,
}

impl BbrCongestion {
    pub fn new() -> Self {
        Self {
            state: BbrState::Startup,
            cwnd: 8.0,
            ssthresh: 256,
            rtt_srtt: 0.0,
            rtt_rttvar: 0.0,
            rtt_initialized: false,
            bw_filter: WindowedFilter::new(Duration::from_secs_f64(10.0)),
            rt_prop_filter: WindowedFilter::new(Duration::from_secs_f64(10.0)),
            max_bw: 1.0,
            min_rtt: Duration::from_millis(10),
            pacing_gain: 2.89,
            cwnd_gain: 2.89,
            inflight: 0.0,
            cycle_count: 0,
            last_cycle_start: Instant::now(),
            probe_rtt_phase: ProbeRttPhase::Enter,
            packet_conservation: false,
            dup_ack_count: 0,
            loss_events: VecDeque::with_capacity(64),
        }
    }
    
    #[inline]
    fn update_rtt(&mut self, now: Instant, rtt: Duration) {
        let rtt_ms = rtt.as_secs_f64() * 1000.0;
        
        if !self.rtt_initialized {
            self.rtt_srtt = rtt_ms;
            self.rtt_rttvar = rtt_ms / 2.0;
            self.rtt_initialized = true;
        } else {
            self.rtt_rttvar = 0.75 * self.rtt_rttvar + 0.25 * (self.rtt_srtt - rtt_ms).abs();
            self.rtt_srtt = 0.875 * self.rtt_srtt + 0.125 * rtt_ms;
        }
        
        self.rt_prop_filter.update(now, rtt_ms);
        if !self.rt_prop_filter.is_empty() {
            self.min_rtt = Duration::from_millis(self.rt_prop_filter.min() as u64);
        }
    }
    
    #[inline]
    fn update_bw(&mut self, now: Instant, bytes: u64, rtt: Duration) {
        if rtt.as_secs_f64() > 0.0 {
            let bw = bytes as f64 / rtt.as_secs_f64();
            self.bw_filter.update(now, bw);
            if !self.bw_filter.is_empty() {
                self.max_bw = self.bw_filter.max();
            }
        }
    }
    
    #[inline]
    fn update_loss_rate(&mut self, now: Instant) -> f64 {
        while let Some(t) = self.loss_events.front() {
            if now.duration_since(*t) > Duration::from_secs(10) {
                self.loss_events.pop_front();
            } else {
                break;
            }
        }
        
        self.loss_events.len() as f64 / 10.0
    }
    
    fn enter_probe_rtt(&mut self, now: Instant) {
        self.state = BbrState::ProbeRtt;
        self.probe_rtt_phase = ProbeRttPhase::Enter;
        self.pacing_gain = 1.0;
        self.cwnd_gain = 1.0;
        self.packet_conservation = true;
        self.last_cycle_start = now;
    }
    
    fn exit_probe_rtt(&mut self, now: Instant) {
        self.state = BbrState::ProbeBw;
        self.probe_rtt_phase = ProbeRttPhase::Exit;
        self.packet_conservation = false;
        self.pacing_gain = 1.25;
        self.cwnd_gain = 2.0;
        self.cycle_count = 0;
        self.last_cycle_start = now;
    }
    
    #[inline]
    fn update_probe_bw_phase(&mut self, now: Instant) {
        if self.state == BbrState::ProbeBw {
            let phase_time = now.duration_since(self.last_cycle_start).as_secs_f64();
            let loss_rate = self.update_loss_rate(now);
            let cycle_time = if loss_rate > 0.1 {
                2.0
            } else if loss_rate > 0.01 {
                4.0
            } else {
                6.0
            };
            
            let phase = (phase_time / cycle_time * 8.0) as usize % 8;
            
            self.pacing_gain = match phase {
                0 => 1.25,
                1 => 0.75,
                _ => 1.0,
            };
            
            if phase_time > cycle_time && self.min_rtt > Duration::from_millis(5) {
                self.enter_probe_rtt(now);
            }
        }
    }
}

impl CongestionControl for BbrCongestion {
    fn on_packet_sent(&mut self, _now: Instant, bytes_sent: u64) {
        self.inflight += bytes_sent as f64;
    }

    fn on_ack(&mut self, now: Instant, bytes_acked: u64, rtt: Option<Duration>) {
        if let Some(rtt) = rtt {
            self.update_rtt(now, rtt);
            self.update_bw(now, bytes_acked, rtt);
        }
        
        self.inflight = (self.inflight - bytes_acked as f64).max(0.0);
        self.dup_ack_count = 0;
        
        match self.state {
            BbrState::Startup => {
                if self.max_bw > 0.0 && self.rtt_initialized {
                    let target = self.max_bw * self.min_rtt.as_secs_f64() * self.cwnd_gain;
                    self.cwnd = target.max(8.0);
                    
                    if self.inflight >= target * 0.75 {
                        self.state = BbrState::Drain;
                        self.pacing_gain = 1.0 / 2.89;
                        self.cwnd_gain = 1.0;
                    }
                }
            }
            BbrState::Drain => {
                if self.max_bw > 0.0 && self.rtt_initialized {
                    let target = self.max_bw * self.min_rtt.as_secs_f64();
                    if self.inflight <= target {
                        self.state = BbrState::ProbeBw;
                        self.pacing_gain = 1.25;
                        self.cwnd_gain = 2.0;
                        self.cycle_count = 0;
                        self.last_cycle_start = now;
                    }
                }
            }
            BbrState::ProbeBw => {
                self.update_probe_bw_phase(now);
                
                if self.max_bw > 0.0 && self.rtt_initialized {
                    let target = self.max_bw * self.min_rtt.as_secs_f64() * self.cwnd_gain;
                    self.cwnd = target.max(8.0);
                }
            }
            BbrState::ProbeRtt => {
                match self.probe_rtt_phase {
                    ProbeRttPhase::Enter => {
                        self.cwnd = 8.0;
                        self.probe_rtt_phase = ProbeRttPhase::Wait;
                    }
                    ProbeRttPhase::Wait => {
                        if now.duration_since(self.last_cycle_start) > Duration::from_millis(100) {
                            self.exit_probe_rtt(now);
                        }
                    }
                    ProbeRttPhase::Exit => {
                        self.exit_probe_rtt(now);
                    }
                }
            }
        }
        
        self.cwnd = self.cwnd.min(1048576.0);
        self.ssthresh = (self.cwnd * 0.5) as u32;
    }

    fn on_loss(&mut self, now: Instant) {
        self.loss_events.push_back(now);
        // BBR does not treat packet loss as a direct bandwidth estimate
        // reduction. max_bw is derived from the time-windowed bandwidth
        // filter and is allowed to age out naturally.
        self.cwnd = (self.cwnd * 0.8).max(4.0);
        self.inflight = (self.inflight * 0.8).max(0.0);
        
        if self.state == BbrState::ProbeBw {
            self.enter_probe_rtt(now);
        }
        
        self.ssthresh = (self.cwnd * 0.5) as u32;
    }

    fn on_timeout(&mut self, now: Instant) {
        self.on_loss(now);
    }
    
    fn on_duplicate_ack(&mut self, _now: Instant) {
        self.dup_ack_count += 1;
        if self.dup_ack_count >= FAST_RETRANSMIT_THRESHOLD {
            self.cwnd = (self.cwnd * 0.9).max(4.0);
            self.dup_ack_count = 0;
        }
    }

    fn cwnd(&self) -> f64 {
        self.cwnd
    }

    fn ssthresh(&self) -> u32 {
        self.ssthresh.max(4)
    }

    fn can_send(&self, in_flight: u32, mtu: u16) -> bool {
        (self.cwnd * mtu as f64) > in_flight as f64
    }

    fn pacing_rate(&self) -> f64 {
        if self.rtt_initialized {
            self.max_bw * self.pacing_gain
        } else {
            self.cwnd / 0.05
        }
    }

    fn pacing_rate_bytes(&self, mtu: u16) -> f64 { if self.rtt_initialized { self.pacing_rate() } else { self.pacing_rate() * mtu as f64 } }

    fn rto(&self) -> Duration {
        if self.rtt_initialized {
            let rto = self.rtt_srtt + 4.0 * self.rtt_rttvar;
            Duration::from_millis(rto.max(MIN_RTO_MS as f64).min(MAX_RTO_MS as f64) as u64)
        } else {
            Duration::from_millis(200)
        }
    }

    fn clone_box(&self) -> Box<dyn CongestionControl> {
        Box::new(self.clone())
    }
}

