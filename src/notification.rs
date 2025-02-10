use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use tokio::sync::{Mutex, Notify};

pub(super) struct NotificationHandler {
    notifiers: Mutex<HashMap<Ipv4Addr, Arc<Notify>>>,
}

impl NotificationHandler {
    pub(super) fn new() -> Self {
        Self {
            notifiers: Mutex::new(HashMap::new()),
        }
    }

    pub(super) async fn register_notifier(&self, src_ip: Ipv4Addr) -> Arc<Notify> {
        let mut notifiers = self.notifiers.lock().await;
        let notifier = Arc::new(Notify::new());
        notifiers.insert(src_ip, notifier.clone());
        notifier
    }

    pub(super) async fn notify(&self, ip: &Ipv4Addr) {
        if let Some(notifier) = self.notifiers.lock().await.remove(ip) {
            notifier.notify_one();
        }
    }
}
