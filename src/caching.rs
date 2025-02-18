use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use pnet::packet::arp::Arp;
use timedmap::TimedMap;

use crate::notification::NotificationHandler;

#[derive(Debug)]
pub(super) struct ArpCache {
    timeout: Duration,
    responses: TimedMap<Ipv4Addr, Arp>,
    notification_handler: Arc<NotificationHandler>,
}

impl ArpCache {
    pub(super) fn new(timeout: Duration, notification_handler: Arc<NotificationHandler>) -> Self {
        Self {
            timeout,
            responses: TimedMap::new(),
            notification_handler,
        }
    }

    pub(super) async fn cache(&self, response: Arp) {
        let ip = response.sender_proto_addr;
        self.responses.insert(ip, response, self.timeout);
        self.notification_handler.notify(&ip).await;
    }

    pub(super) fn get(&self, ip: &Ipv4Addr) -> Option<Arp> {
        self.responses.get(ip)
    }
}
