use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    pub child_ip: IpAddr,
    pub child_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
}

impl FlowKey {
    pub fn remote_addr(&self) -> SocketAddr {
        SocketAddr::new(self.remote_ip, self.remote_port)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpSession {
    pub child_initial_seq: u32,
    pub child_next_seq: u32,
    pub engine_initial_seq: u32,
    pub engine_next_seq: u32,
    pub fin_from_child: bool,
    pub fin_from_remote: bool,
}

impl TcpSession {
    pub fn new(child_initial_seq: u32, engine_initial_seq: u32) -> Self {
        Self {
            child_initial_seq,
            child_next_seq: child_initial_seq.wrapping_add(1),
            engine_initial_seq,
            engine_next_seq: engine_initial_seq.wrapping_add(1),
            fin_from_child: false,
            fin_from_remote: false,
        }
    }

    #[cfg(test)]
    pub fn child_ack_for_engine_syn(&self) -> u32 {
        self.engine_initial_seq.wrapping_add(1)
    }

    #[cfg(test)]
    pub fn child_acknowledges_handshake(&self, ack_number: u32) -> bool {
        ack_number == self.child_ack_for_engine_syn()
    }

    pub fn accept_child_payload(&mut self, seq: u32, payload_len: usize) -> bool {
        if seq != self.child_next_seq {
            return false;
        }
        self.child_next_seq = self.child_next_seq.wrapping_add(payload_len as u32);
        true
    }

    pub fn accept_child_fin(&mut self, seq: u32) -> bool {
        if seq != self.child_next_seq {
            return false;
        }
        self.child_next_seq = self.child_next_seq.wrapping_add(1);
        self.fin_from_child = true;
        true
    }

    pub fn reserve_engine_payload_seq(&mut self, payload_len: usize) -> u32 {
        let seq = self.engine_next_seq;
        self.engine_next_seq = self.engine_next_seq.wrapping_add(payload_len as u32);
        seq
    }

    pub fn reserve_engine_fin_seq(&mut self) -> u32 {
        let seq = self.engine_next_seq;
        self.engine_next_seq = self.engine_next_seq.wrapping_add(1);
        self.fin_from_remote = true;
        seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn key() -> FlowKey {
        FlowKey {
            child_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            child_port: 40000,
            remote_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            remote_port: 443,
        }
    }

    #[test]
    fn flow_key_renders_remote_socket_addr() {
        assert_eq!(
            key().remote_addr(),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443))
        );
    }

    #[test]
    fn tcp_session_tracks_sequence_progress() {
        let mut session = TcpSession::new(100, 500);
        assert!(session.child_acknowledges_handshake(501));
        assert!(session.accept_child_payload(101, 4));
        assert_eq!(session.child_next_seq, 105);
        assert_eq!(session.reserve_engine_payload_seq(7), 501);
        assert_eq!(session.engine_next_seq, 508);
        assert!(session.accept_child_fin(105));
        assert_eq!(session.child_next_seq, 106);
        assert_eq!(session.reserve_engine_fin_seq(), 508);
        assert!(session.fin_from_child);
        assert!(session.fin_from_remote);
    }
}
