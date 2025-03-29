use lazy_static::lazy_static;
use prometheus::{GaugeVec, HistogramVec, IntCounterVec, Registry};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref PROXY_METRICS: ProxyMetrics = ProxyMetrics::new();
}

pub struct ProxyMetrics {
    pub requests_total: IntCounterVec,
    pub request_duration: HistogramVec,
    pub certificate_operations: IntCounterVec,
    pub backend_failures: IntCounterVec,
    pub certificate_expiry: GaugeVec,
    // New metrics
    pub active_connections: GaugeVec,
    pub swarm_operations: IntCounterVec,
    pub lock_operations: IntCounterVec,
}

impl ProxyMetrics {
    fn new() -> Self {
        let requests_total = IntCounterVec::new(
            prometheus::Opts::new("proxy_requests_total", "Total number of proxy requests"),
            &["domain", "status"],
        )
        .unwrap();

        let request_duration = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "proxy_request_duration_seconds",
                "Request duration in seconds",
            ),
            &["domain"],
        )
        .unwrap();

        let certificate_operations = IntCounterVec::new(
            prometheus::Opts::new(
                "certificate_operations_total",
                "Total number of certificate operations",
            ),
            &["domain", "operation", "status"],
        )
        .unwrap();

        let backend_failures = IntCounterVec::new(
            prometheus::Opts::new("backend_failures_total", "Total number of backend failures"),
            &["backend", "reason"],
        )
        .unwrap();

        let certificate_expiry = GaugeVec::new(
            prometheus::Opts::new(
                "certificate_expiry_seconds",
                "Seconds until certificate expiry",
            ),
            &["domain"],
        )
        .unwrap();

        let active_connections = GaugeVec::new(
            prometheus::Opts::new("active_connections", "Number of active connections"),
            &["type"],
        )
        .unwrap();

        let swarm_operations = IntCounterVec::new(
            prometheus::Opts::new("swarm_operations_total", "Total number of swarm operations"),
            &["operation", "status"],
        )
        .unwrap();

        let lock_operations = IntCounterVec::new(
            prometheus::Opts::new(
                "lock_operations_total",
                "Total number of distributed lock operations",
            ),
            &["operation", "status"],
        )
        .unwrap();

        // Register all metrics
        let metrics = Self {
            requests_total: requests_total.clone(),
            request_duration: request_duration.clone(),
            certificate_operations: certificate_operations.clone(),
            backend_failures: backend_failures.clone(),
            certificate_expiry: certificate_expiry.clone(),
            active_connections: active_connections.clone(),
            swarm_operations: swarm_operations.clone(),
            lock_operations: lock_operations.clone(),
        };

        // Register with the registry
        REGISTRY.register(Box::new(requests_total)).unwrap_or(());
        REGISTRY.register(Box::new(request_duration)).unwrap_or(());
        REGISTRY
            .register(Box::new(certificate_operations))
            .unwrap_or(());
        REGISTRY.register(Box::new(backend_failures)).unwrap_or(());
        REGISTRY
            .register(Box::new(certificate_expiry))
            .unwrap_or(());
        REGISTRY
            .register(Box::new(active_connections))
            .unwrap_or(());
        REGISTRY.register(Box::new(swarm_operations)).unwrap_or(());
        REGISTRY.register(Box::new(lock_operations)).unwrap_or(());

        metrics
    }
}
