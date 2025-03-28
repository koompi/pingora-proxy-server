use lazy_static::lazy_static;
use prometheus::{HistogramVec, IntCounterVec, Registry};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref PROXY_METRICS: ProxyMetrics = ProxyMetrics::new();
}

pub struct ProxyMetrics {
    pub requests_total: IntCounterVec,
    pub request_duration: HistogramVec,
    pub certificate_operations: IntCounterVec,
    pub backend_failures: IntCounterVec,
}

impl ProxyMetrics {
    fn new() -> Self {
        // Create metrics using low-level API to ensure correct types
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

        // Register metrics with the registry
        REGISTRY
            .register(Box::new(requests_total.clone()))
            .unwrap_or(());
        REGISTRY
            .register(Box::new(request_duration.clone()))
            .unwrap_or(());
        REGISTRY
            .register(Box::new(certificate_operations.clone()))
            .unwrap_or(());
        REGISTRY
            .register(Box::new(backend_failures.clone()))
            .unwrap_or(());

        ProxyMetrics {
            requests_total,
            request_duration,
            certificate_operations,
            backend_failures,
        }
    }
}
