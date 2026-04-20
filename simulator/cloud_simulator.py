"""
Cloud Infrastructure Simulator
Gerçekçi Kubernetes cluster olaylarını simüle eder.
Gerçek bir cluster'a ihtiyaç duymadan LLM remediation'ı test edilebilir.
"""
import random
import time
import uuid
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class PodStatus(str, Enum):
    RUNNING = "Running"
    CRASH_LOOP = "CrashLoopBackOff"
    OOM_KILLED = "OOMKilled"
    PENDING = "Pending"
    ERROR = "Error"
    IMAGE_PULL_BACK_OFF = "ImagePullBackOff"
    EVICTED = "Evicted"
    TERMINATING = "Terminating"
    INIT_ERROR = "Init:Error"
    NOT_READY = "Running (0/1)"


class IncidentCategory(str, Enum):
    POD_LIFECYCLE = "Pod Yaşam Döngüsü"
    NETWORK = "Ağ & Bağlantı"
    STORAGE = "Depolama"
    SECURITY = "Güvenlik"
    CONFIGURATION = "Konfigürasyon"
    CLUSTER = "Cluster & Orkestrasyon"


@dataclass
class PodInfo:
    name: str
    namespace: str
    status: str
    restarts: int
    cpu_usage: float
    memory_usage: float
    memory_limit_mb: int
    age_hours: int
    labels: dict = field(default_factory=dict)


@dataclass
class ServiceInfo:
    name: str
    namespace: str
    pods: list
    latency_ms: float
    error_rate: float
    requests_per_sec: float
    dependencies: list = field(default_factory=list)


@dataclass
class Alert:
    id: str
    timestamp: str
    severity: str
    title: str
    description: str
    source_service: str
    namespace: str
    metrics: dict
    pod_info: Optional[dict] = None
    related_services: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


# ═══════════════════════════════════════════════════════
# Detaylı Senaryo Tanımları — 20 Gerçekçi Kubernetes Incident
# ═══════════════════════════════════════════════════════

INCIDENT_SCENARIOS = [

    # ──────────────────────────────────────
    # POD YAŞAM DÖNGÜSÜ
    # ──────────────────────────────────────
    {
        "id": "oom_kill_memory_leak",
        "title": "OOMKilled - Memory Leak Detected",
        "category": IncidentCategory.POD_LIFECYCLE,
        "severity": Severity.CRITICAL,
        "service": "payment-service",
        "namespace": "production",
        "description": "payment-service pod'ları sürekli OOMKilled hatası alıyor. "
                       "Son 30 dakikada çok sayıda restart gerçekleşti. "
                       "Memory kullanımı pod başına 512MB limitini aşıyor. "
                       "Olası neden: v2.3.1 güncellemesinde tanıtılan memory leak.",
        "metrics": {
            "pod_restarts_30m": 12,
            "memory_usage_percent": 98,
            "cpu_usage_percent": 45,
            "error_rate_percent": 35,
            "latency_p99_ms": 4500,
            "affected_pods": 3,
            "total_pods": 5
        },
        "pod_info": {
            "name": "payment-service-7d4f8b6c9-{suffix}",
            "status": PodStatus.OOM_KILLED,
            "restarts": 12,
            "memory_limit_mb": 512,
            "memory_usage_percent": 98,
            "cpu_usage_percent": 45
        },
        "related_services": ["order-service", "notification-service"],
        "expected_actions": [
            "Pod loglarını inceleme",
            "Memory limiti artırma veya rollback",
            "Deployment restart",
            "Monitoring artırma"
        ],
        "root_cause": "v2.3.1 güncellemesinde connection pool nesneleri düzgün kapatılmıyor, "
                      "her request'te yeni connection oluşturuluyor ama eski connection'lar GC tarafından toplanamıyor.",
        "optimal_fix": "kubectl rollout undo deployment/payment-service -n production"
    },
    {
        "id": "crash_loop_backoff",
        "title": "CrashLoopBackOff - Missing Environment Variable",
        "category": IncidentCategory.POD_LIFECYCLE,
        "severity": Severity.CRITICAL,
        "service": "notification-service",
        "namespace": "production",
        "description": "notification-service pod'ları CrashLoopBackOff durumunda. "
                       "Son ConfigMap güncellemesinde SMTP_HOST environment variable'ı kaldırılmış. "
                       "Pod başlangıçta config validation'da fail ediyor ve sürekli restart oluyor.",
        "metrics": {
            "pod_restarts_30m": 24,
            "crash_loop_duration_min": 45,
            "error_rate_percent": 100,
            "healthy_replicas": 0,
            "desired_replicas": 3,
            "last_successful_start_min": 47
        },
        "pod_info": {
            "name": "notification-service-8e5f6a7b9-{suffix}",
            "status": PodStatus.CRASH_LOOP,
            "restarts": 24,
            "memory_limit_mb": 256,
            "memory_usage_percent": 10,
            "cpu_usage_percent": 5
        },
        "related_services": ["smtp-relay", "config-service"],
        "expected_actions": [
            "Pod events ve logları kontrol et",
            "ConfigMap içeriğini doğrula",
            "Son deployment değişikliklerini incele",
            "Eksik env variable'ı ekle veya rollback yap"
        ],
        "root_cause": "ConfigMap güncellemesi sırasında SMTP_HOST key'i yanlışlıkla silinmiş. "
                      "Pod startup'ta bu zorunlu variable'ı bulamayınca panic ile çıkıyor.",
        "optimal_fix": "kubectl patch configmap notification-config -n production --type merge -p '{\"data\":{\"SMTP_HOST\":\"smtp.internal.svc.cluster.local\"}}'"
    },
    {
        "id": "image_pull_backoff",
        "title": "ImagePullBackOff - Container Registry Auth Failure",
        "category": IncidentCategory.POD_LIFECYCLE,
        "severity": Severity.HIGH,
        "service": "catalog-service",
        "namespace": "staging",
        "description": "catalog-service yeni deployment'ı ImagePullBackOff durumunda. "
                       "Container registry token'ı expire olmuş. "
                       "Staging ortamında tüm yeni pod'lar image pull yapamıyor.",
        "metrics": {
            "pending_pods": 4,
            "desired_replicas": 4,
            "available_replicas": 0,
            "registry_auth_failures": 12,
            "last_successful_pull_hours": 26
        },
        "pod_info": {
            "name": "catalog-service-2b3c4d5e6-{suffix}",
            "status": PodStatus.IMAGE_PULL_BACK_OFF,
            "restarts": 0,
            "memory_limit_mb": 512,
            "memory_usage_percent": 0,
            "cpu_usage_percent": 0
        },
        "related_services": ["container-registry", "image-scanner"],
        "expected_actions": [
            "Pod events ile pull hatasını doğrula",
            "imagePullSecret'ın geçerliliğini kontrol et",
            "Registry erişimini test et",
            "Secret'ı yenile ve pod'ları restart et"
        ],
        "root_cause": "Docker registry imagePullSecret'ı 24 saat önce expire olmuş. "
                      "Otomatik token renewal CronJob'ı RBAC hatası nedeniyle çalışmıyor.",
        "optimal_fix": "kubectl create secret docker-registry regcred --docker-server=registry.example.com --docker-username=svc-account --docker-password=$(vault read -field=token secret/registry) -n staging --dry-run=client -o yaml | kubectl apply -f -"
    },
    {
        "id": "liveness_probe_failure",
        "title": "Liveness Probe Failure - Cascading Pod Restarts",
        "category": IncidentCategory.POD_LIFECYCLE,
        "severity": Severity.HIGH,
        "service": "search-service",
        "namespace": "production",
        "description": "search-service pod'larının liveness probe'ları başarısız oluyor. "
                       "Upstream ElasticSearch cluster yavaşladığı için /health endpoint'i timeout veriyor. "
                       "Kubernetes pod'ları sürekli restart ediyor ama asıl sorun ES cluster'da.",
        "metrics": {
            "pod_restarts_1h": 18,
            "probe_timeout_ms": 5000,
            "probe_failure_threshold": 3,
            "healthy_pods": 1,
            "total_pods": 5,
            "upstream_latency_ms": 8500
        },
        "pod_info": {
            "name": "search-service-4c5d6e7f8-{suffix}",
            "status": PodStatus.NOT_READY,
            "restarts": 18,
            "memory_limit_mb": 1024,
            "memory_usage_percent": 55,
            "cpu_usage_percent": 30
        },
        "related_services": ["elasticsearch-cluster", "kibana", "indexer-service"],
        "expected_actions": [
            "Liveness probe loglarını kontrol et",
            "Upstream ES cluster sağlığını doğrula",
            "Probe timeout süresini geçici artır",
            "ES cluster sorununu çöz"
        ],
        "root_cause": "ElasticSearch cluster'da bir data node disk'i dolmuş ve shard relocation başlamış. "
                      "Bu durum ES query latency'sini artırıp search-service'in health endpoint'ini yavaşlatıyor.",
        "optimal_fix": "kubectl patch deployment search-service -n production -p '{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"search-service\",\"livenessProbe\":{\"timeoutSeconds\":15}}]}}}}' && ES disk sorununu paralel çöz"
    },

    # ──────────────────────────────────────
    # AĞ & BAĞLANTI
    # ──────────────────────────────────────
    {
        "id": "cascading_latency",
        "title": "Cascading Latency Spike - Database Connection Exhaustion",
        "category": IncidentCategory.NETWORK,
        "severity": Severity.CRITICAL,
        "service": "order-processing-service",
        "namespace": "production",
        "description": "order-processing-service latency'si 200ms'den 8000ms'ye yükseldi. "
                       "PostgreSQL connection pool tükenmiş durumda. "
                       "Downstream servisler de etkileniyor: inventory-service, shipping-service. "
                       "HPA max replica sayısına ulaştı ancak sorun devam ediyor.",
        "metrics": {
            "latency_p99_ms": 8000,
            "latency_p50_ms": 3500,
            "error_rate_percent": 42,
            "db_active_connections": 100,
            "db_max_connections": 100,
            "db_waiting_queries": 250,
            "requests_per_sec": 1200,
            "hpa_current_replicas": 10,
            "hpa_max_replicas": 10
        },
        "pod_info": {
            "name": "order-processing-5f8c9d7b2-{suffix}",
            "status": PodStatus.RUNNING,
            "restarts": 0,
            "memory_limit_mb": 1024,
            "memory_usage_percent": 72,
            "cpu_usage_percent": 88
        },
        "related_services": ["inventory-service", "shipping-service", "postgresql-primary"],
        "expected_actions": [
            "DB connection pool metriklerini inceleme",
            "Slow query analizi",
            "Connection pool limitini artırma",
            "Gerekirse read replica ekleme"
        ],
        "root_cause": "Yavaş bir analitik sorgu (EXPLAIN ANALYZE ile 45s) kilit tutuyor ve "
                      "connection pool'u tüketiyor. Bu sorgu cronjob'dan kaynaklanıyor.",
        "optimal_fix": "Cronjob'u durdur: kubectl delete cronjob analytics-daily -n production, "
                       "ardından connection pool'u flush et"
    },
    {
        "id": "dns_resolution_failure",
        "title": "DNS Resolution Failure - CoreDNS Degradation",
        "category": IncidentCategory.NETWORK,
        "severity": Severity.CRITICAL,
        "service": "coredns",
        "namespace": "kube-system",
        "description": "CoreDNS pod'ları yüksek yük altında ve DNS çözümleme gecikmeli. "
                       "Cluster genelinde servisler arası iletişim bozuluyor. "
                       "5xx error rate tüm servislerde yükseliyor.",
        "metrics": {
            "dns_failure_rate_percent": 35,
            "dns_latency_ms": 2500,
            "normal_dns_latency_ms": 5,
            "affected_services": 15,
            "coredns_memory_usage_percent": 95,
            "cluster_5xx_rate_percent": 28
        },
        "pod_info": {
            "name": "coredns-5f9c7d8e4-{suffix}",
            "status": PodStatus.RUNNING,
            "restarts": 0,
            "memory_limit_mb": 170,
            "memory_usage_percent": 95,
            "cpu_usage_percent": 92
        },
        "related_services": ["kube-proxy", "kube-apiserver", "all-services"],
        "expected_actions": [
            "CoreDNS pod kaynak kullanımını kontrol et",
            "DNS resolution test yap (nslookup)",
            "CoreDNS replica sayısını artır",
            "DNS cache yapılandırmasını optimize et"
        ],
        "root_cause": "Yeni deploy edilen bir microservice düzensiz DNS sorguları gönderiyor (retry storm). "
                      "Her failed request 5 DNS lookup tetikliyor ve CoreDNS'i boğuyor.",
        "optimal_fix": "kubectl scale deployment coredns -n kube-system --replicas=5 && sorunlu servisi düzelt"
    },
    {
        "id": "ingress_backend_502",
        "title": "Ingress 502 Bad Gateway - Backend Unavailable",
        "category": IncidentCategory.NETWORK,
        "severity": Severity.HIGH,
        "service": "ingress-nginx",
        "namespace": "ingress",
        "description": "Ingress controller 502 Bad Gateway hatası döndürüyor. "
                       "Backend checkout-service pod'larının readiness probe'ları henüz pass etmemiş. "
                       "Yeni deployment sonrası endpoint listesi güncellenmedi.",
        "metrics": {
            "error_502_rate_percent": 15,
            "total_requests_per_sec": 3500,
            "affected_routes": 4,
            "healthy_endpoints": 2,
            "total_endpoints": 6,
            "upstream_response_time_ms": 12000
        },
        "pod_info": {
            "name": "ingress-nginx-controller-6a7b8c9d-{suffix}",
            "status": PodStatus.RUNNING,
            "restarts": 0,
            "memory_limit_mb": 512,
            "memory_usage_percent": 60,
            "cpu_usage_percent": 75
        },
        "related_services": ["checkout-service", "frontend-app", "load-balancer"],
        "expected_actions": [
            "Ingress controller loglarını incele",
            "Backend endpoint sağlığını doğrula",
            "Readiness probe yapılandırmasını kontrol et",
            "Geçici olarak eski pod'lara trafik yönlendir"
        ],
        "root_cause": "checkout-service'in yeni versiyonu startup süresi 90 saniyeye çıkmış "
                      "ancak readiness probe initialDelaySeconds hâlâ 10 saniye. Pod hazır olmadan trafik alıyor.",
        "optimal_fix": "kubectl patch deployment checkout-service -n production -p '{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"checkout-service\",\"readinessProbe\":{\"initialDelaySeconds\":120}}]}}}}'"
    },

    # ──────────────────────────────────────
    # DEPOLAMA
    # ──────────────────────────────────────
    {
        "id": "node_pressure",
        "title": "Node Resource Pressure - Disk I/O Saturation",
        "category": IncidentCategory.STORAGE,
        "severity": Severity.HIGH,
        "service": "logging-pipeline",
        "namespace": "monitoring",
        "description": "worker-node-03 disk I/O %100 saturasyona ulaştı. "
                       "ElasticSearch pod'ları yavaşladı, log ingestion pipeline durma noktasında. "
                       "Node üzerindeki diğer pod'lar da etkileniyor. "
                       "DiskPressure taint uygulandı.",
        "metrics": {
            "disk_io_utilization_percent": 100,
            "disk_read_mbps": 450,
            "disk_write_mbps": 320,
            "iops_current": 15000,
            "iops_limit": 16000,
            "node_disk_usage_percent": 89,
            "pending_pods": 5,
            "logs_dropped_per_sec": 2500
        },
        "pod_info": {
            "name": "elasticsearch-data-{numeric_suffix}",
            "status": PodStatus.RUNNING,
            "restarts": 0,
            "memory_limit_mb": 4096,
            "memory_usage_percent": 82,
            "cpu_usage_percent": 65
        },
        "related_services": ["fluentd", "kibana", "prometheus"],
        "expected_actions": [
            "Eski index'leri silme/arşivleme",
            "Log retention policy güncelleme",
            "Pod'ları başka node'a taşıma",
            "Disk I/O limitlerini artırma"
        ],
        "root_cause": "ILM (Index Lifecycle Management) policy'si 90 günlük retention yapılandırılmış "
                      "ancak disk boyutu bunu karşılayamıyor. Son 1 haftada log hacmi 3x arttı.",
        "optimal_fix": "ES eski index'leri sil: curator_cli --config /etc/curator/config.yml delete_indices --older-than 30"
    },
    {
        "id": "pvc_mount_failure",
        "title": "PVC Mount Failure - StorageClass Provisioner Error",
        "category": IncidentCategory.STORAGE,
        "severity": Severity.HIGH,
        "service": "analytics-service",
        "namespace": "production",
        "description": "analytics-service pod'ları PVC mount edemediği için Pending durumunda. "
                       "Cloud provider disk quota'sı aşılmış. Yeni PersistentVolume provision edilemiyor.",
        "metrics": {
            "pending_pods": 3,
            "pvc_pending_count": 3,
            "disk_quota_used_percent": 100,
            "provisioner_errors_1h": 12,
            "data_pipeline_delay_min": 35
        },
        "pod_info": {
            "name": "analytics-service-7f8g9h0i1-{suffix}",
            "status": PodStatus.PENDING,
            "restarts": 0,
            "memory_limit_mb": 2048,
            "memory_usage_percent": 0,
            "cpu_usage_percent": 0
        },
        "related_services": ["storage-provisioner", "cloud-controller-manager"],
        "expected_actions": [
            "PVC durumunu ve events'lerini kontrol et",
            "Cloud provider disk quota'sını doğrula",
            "StorageClass provisioner loglarını incele",
            "Quota artırma veya kullanılmayan PV'leri temizle"
        ],
        "root_cause": "Cloud provider hesabındaki persistent disk quota'sı aşılmış. "
                      "Geliştirme ortamında bırakılmış 15 kullanılmayan PV quota'yı dolduruyor.",
        "optimal_fix": "Kullanılmayan PV'leri temizle: kubectl get pv --no-headers | grep Released | awk '{print $1}' | xargs kubectl delete pv"
    },
    {
        "id": "persistent_volume_full",
        "title": "PersistentVolume Full - Database Write Blocked",
        "category": IncidentCategory.STORAGE,
        "severity": Severity.CRITICAL,
        "service": "postgresql-primary",
        "namespace": "production",
        "description": "PostgreSQL primary instance disk'i doldu. "
                       "WAL (Write-Ahead Log) dosyaları birikerek alanı tüketti. "
                       "Veritabanı read-only moduna geçti, tüm write işlemleri reddediliyor.",
        "metrics": {
            "disk_usage_percent": 97,
            "wal_size_gb": 45,
            "total_disk_gb": 50,
            "write_blocked": True,
            "replication_lag_sec": 120,
            "affected_services_count": 8
        },
        "pod_info": {
            "name": "postgresql-primary-0",
            "status": PodStatus.RUNNING,
            "restarts": 0,
            "memory_limit_mb": 8192,
            "memory_usage_percent": 70,
            "cpu_usage_percent": 25
        },
        "related_services": ["postgresql-replica", "pgbouncer", "backup-service"],
        "expected_actions": [
            "WAL dosya boyutlarını kontrol et",
            "Eski WAL segment'lerini temizle",
            "Replication slot'ları kontrol et (inactive slot WAL birikimine neden olur)",
            "Disk boyutunu genişlet"
        ],
        "root_cause": "Devre dışı bırakılan bir replica'nın replication slot'u hâlâ aktif. "
                      "PostgreSQL bu slot için WAL segment'lerini silemiyor ve disk doluyor.",
        "optimal_fix": "SELECT pg_drop_replication_slot('replica_old_slot'); ve ardından CHECKPOINT çalıştır"
    },

    # ──────────────────────────────────────
    # GÜVENLİK
    # ──────────────────────────────────────
    {
        "id": "security_breach_attempt",
        "title": "Security Alert - Suspicious Pod Activity",
        "category": IncidentCategory.SECURITY,
        "severity": Severity.CRITICAL,
        "service": "user-auth-service",
        "namespace": "production",
        "description": "user-auth-service pod'undan beklenmeyen outbound network bağlantıları tespit edildi. "
                       "Pod içinden crypto mining binary'si indirilmeye çalışılıyor. "
                       "Container image vulnerability scan'de CVE-2026-1234 bulundu. "
                       "Olası container escape girişimi.",
        "metrics": {
            "outbound_connections_anomaly": True,
            "suspicious_processes": ["xmrig", "curl suspicious-domain.com"],
            "cve_count_critical": 3,
            "network_bytes_out_mbps": 85,
            "normal_network_bytes_out_mbps": 2,
            "failed_auth_attempts_per_min": 450,
            "normal_auth_attempts_per_min": 50
        },
        "pod_info": {
            "name": "user-auth-service-3a4b5c6d7-{suffix}",
            "status": PodStatus.RUNNING,
            "restarts": 0,
            "memory_limit_mb": 512,
            "memory_usage_percent": 91,
            "cpu_usage_percent": 95
        },
        "related_services": ["redis-session-store", "user-db", "oauth-provider"],
        "expected_actions": [
            "Pod'u izole et (network policy)",
            "Forensic analiz için pod snapshot al",
            "Güvenli image ile redeploy",
            "Secret rotation başlat"
        ],
        "root_cause": "Base image'deki güncel olmayan OpenSSL kütüphanesi "
                      "(CVE-2026-1234) üzerinden remote code execution.",
        "optimal_fix": "kubectl network-policy isolate pod, snapshot, then kubectl rollout restart with patched image"
    },
    {
        "id": "rbac_permission_denied",
        "title": "RBAC Misconfiguration - Service Account Denied",
        "category": IncidentCategory.SECURITY,
        "severity": Severity.MEDIUM,
        "service": "deployment-controller",
        "namespace": "production",
        "description": "CI/CD pipeline'ındaki service account RBAC izinleri kısıtlanmış. "
                       "Yeni deployment'lar oluşturulamıyor. "
                       "Son ClusterRole güncellemesinde deployment/create izni kaldırılmış.",
        "metrics": {
            "permission_denied_count_1h": 45,
            "failed_deployments": 6,
            "affected_pipelines": 3,
            "last_successful_deploy_hours": 4
        },
        "pod_info": {
            "name": "argocd-application-controller-0",
            "status": PodStatus.RUNNING,
            "restarts": 0,
            "memory_limit_mb": 512,
            "memory_usage_percent": 40,
            "cpu_usage_percent": 15
        },
        "related_services": ["argocd-server", "github-webhook", "tekton-pipelines"],
        "expected_actions": [
            "ClusterRole ve RoleBinding'i kontrol et",
            "Son RBAC değişikliklerini audit et",
            "Service account izinlerini düzelt",
            "Pipeline'ları yeniden çalıştır"
        ],
        "root_cause": "Platform ekibi güvenlik hardening sırasında ClusterRole'dan 'deployments' resource'unu "
                      "yanlışlıkla kaldırmış. CI/CD service account artık deployment oluşturamıyor.",
        "optimal_fix": "kubectl patch clusterrole cicd-deployer --type=json -p='[{\"op\":\"add\",\"path\":\"/rules/-\",\"value\":{\"apiGroups\":[\"apps\"],\"resources\":[\"deployments\"],\"verbs\":[\"create\",\"update\",\"patch\"]}}]'"
    },
    {
        "id": "secret_leak_detection",
        "title": "Secret Leak - Credentials Exposed in Pod Logs",
        "category": IncidentCategory.SECURITY,
        "severity": Severity.CRITICAL,
        "service": "auth-service",
        "namespace": "production",
        "description": "auth-service pod loglarında database credentials plain text olarak görünüyor. "
                       "Debug mode yanlışlıkla production'da açık bırakılmış. "
                       "Loglar external log aggregator'a da gönderilmiş durumda.",
        "metrics": {
            "exposed_secrets_count": 3,
            "log_entries_with_secrets": 847,
            "hours_since_exposure": 2,
            "external_log_systems_affected": 2,
            "users_potentially_affected": 15000
        },
        "pod_info": {
            "name": "auth-service-5e6f7g8h9-{suffix}",
            "status": PodStatus.RUNNING,
            "restarts": 0,
            "memory_limit_mb": 512,
            "memory_usage_percent": 55,
            "cpu_usage_percent": 30
        },
        "related_services": ["log-aggregator", "elasticsearch-logs", "user-db"],
        "expected_actions": [
            "Debug mode'u hemen kapat",
            "Exposed credential'ları rotate et",
            "Log sistemlerinden hassas verileri temizle",
            "Incident response protokolünü başlat"
        ],
        "root_cause": "Son deployment'ta LOG_LEVEL=debug olarak set edilmiş ve application tüm request/response "
                      "body'lerini (DB credential'lar dahil) logluyor.",
        "optimal_fix": "kubectl set env deployment/auth-service LOG_LEVEL=warn -n production && tüm secret'ları rotate et"
    },

    # ──────────────────────────────────────
    # KONFİGÜRASYON
    # ──────────────────────────────────────
    {
        "id": "config_drift_ssl",
        "title": "Configuration Drift - SSL Certificate Expiry",
        "category": IncidentCategory.CONFIGURATION,
        "severity": Severity.HIGH,
        "service": "api-gateway",
        "namespace": "ingress",
        "description": "api-gateway SSL sertifikası birkaç saat içinde sona erecek. "
                       "cert-manager renewal başarısız oldu. "
                       "DNS challenge doğrulaması timeout veriyor. "
                       "Yenileme başarısız olursa tüm HTTPS trafiği kesilecek.",
        "metrics": {
            "cert_expiry_hours": 2,
            "renewal_attempts": 3,
            "renewal_failures": 3,
            "last_error": "DNS01 challenge timeout after 120s",
            "affected_domains": ["api.example.com", "payments.example.com"],
            "https_traffic_percent": 99.8
        },
        "pod_info": {
            "name": "cert-manager-7c8d9e1f2-{suffix}",
            "status": PodStatus.RUNNING,
            "restarts": 0,
            "memory_limit_mb": 256,
            "memory_usage_percent": 35,
            "cpu_usage_percent": 12
        },
        "related_services": ["cert-manager", "external-dns", "ingress-nginx"],
        "expected_actions": [
            "cert-manager loglarını kontrol etme",
            "DNS provider erişimini doğrulama",
            "Manuel sertifika yenileme",
            "HTTP01 challenge'a geçiş"
        ],
        "root_cause": "DNS provider API key'i rotate edilmiş ancak cert-manager secret'ı güncellenmemiş.",
        "optimal_fix": "kubectl create secret generic dns-credentials --from-literal=api-key=NEW_KEY -n cert-manager --dry-run=client -o yaml | kubectl apply -f -"
    },
    {
        "id": "configmap_not_found",
        "title": "ConfigMap Not Found - Application Startup Failure",
        "category": IncidentCategory.CONFIGURATION,
        "severity": Severity.HIGH,
        "service": "billing-service",
        "namespace": "production",
        "description": "billing-service yeni pod'ları ConfigMap bulunamadığı için başlatılamıyor. "
                       "Namespace migration sırasında billing-config ConfigMap'i kopyalanmamış. "
                       "Mevcut pod'lar çalışıyor ama scale-up veya restart mümkün değil.",
        "metrics": {
            "pending_pods": 2,
            "running_pods": 3,
            "missing_configmaps": 1,
            "failed_scheduling_events": 8,
            "service_degraded": True
        },
        "pod_info": {
            "name": "billing-service-9h0i1j2k3-{suffix}",
            "status": PodStatus.PENDING,
            "restarts": 0,
            "memory_limit_mb": 512,
            "memory_usage_percent": 0,
            "cpu_usage_percent": 0
        },
        "related_services": ["payment-gateway", "invoice-service"],
        "expected_actions": [
            "Pod events'lerini kontrol et",
            "Eksik ConfigMap'i belirle",
            "ConfigMap'i doğru namespace'e oluştur",
            "Pod'ların schedule edilmesini bekle"
        ],
        "root_cause": "Namespace migration script'i ConfigMap'leri kopyalamayı atlamış. "
                      "billing-config ConfigMap'i yeni namespace'te yok.",
        "optimal_fix": "kubectl get configmap billing-config -n old-namespace -o yaml | sed 's/namespace: old-namespace/namespace: production/' | kubectl apply -f -"
    },
    {
        "id": "resource_quota_exceeded",
        "title": "Resource Quota Exceeded - Namespace Limit Reached",
        "category": IncidentCategory.CONFIGURATION,
        "severity": Severity.HIGH,
        "service": "data-pipeline",
        "namespace": "production",
        "description": "Production namespace resource quota aşıldı. "
                       "Yeni pod'lar schedule edilemiyor. HPA scale-up komutları başarısız. "
                       "CPU quota tükenmiş, memory quota'sı da limite yakın.",
        "metrics": {
            "cpu_quota_used_percent": 100,
            "memory_quota_used_percent": 94,
            "pending_pods": 7,
            "rejected_pod_creates": 12,
            "hpa_unable_to_scale_count": 3
        },
        "pod_info": {
            "name": "data-pipeline-runner-1a2b3c4d-{suffix}",
            "status": PodStatus.PENDING,
            "restarts": 0,
            "memory_limit_mb": 2048,
            "memory_usage_percent": 0,
            "cpu_usage_percent": 0
        },
        "related_services": ["spark-operator", "airflow-scheduler", "data-warehouse"],
        "expected_actions": [
            "Namespace ResourceQuota kullanımını kontrol et",
            "İdeal olmayan pod'ları belirle ve temizle",
            "Quota limitlerini artır veya optimize et",
            "HPA'ları geçici olarak devre dışı bırak"
        ],
        "root_cause": "Tamamlanmış ama silinmemiş Spark job pod'ları (Completed durumunda) "
                      "hâlâ resource quota'dan yer tutuyor. 25 zombie pod quota'yı dolduruyor.",
        "optimal_fix": "kubectl delete pods --field-selector=status.phase=Succeeded -n production && kubectl delete pods --field-selector=status.phase=Failed -n production"
    },

    # ──────────────────────────────────────
    # CLUSTER & ORKESTRASYON
    # ──────────────────────────────────────
    {
        "id": "node_not_ready",
        "title": "Node NotReady - Kubelet Communication Failure",
        "category": IncidentCategory.CLUSTER,
        "severity": Severity.CRITICAL,
        "service": "kubelet",
        "namespace": "kube-system",
        "description": "worker-node-02 NotReady durumuna düştü. "
                       "Kubelet heartbeat göndermiyor. "
                       "Node üzerindeki pod'lar etkilendi, taint eklendi ve pod eviction başladı.",
        "metrics": {
            "node_heartbeat_missed_sec": 300,
            "pods_on_node": 12,
            "evicting_pods": 8,
            "rescheduled_pods": 4,
            "cluster_cpu_remaining_percent": 35,
            "failed_health_checks": 15
        },
        "pod_info": {
            "name": "kube-proxy-{suffix}",
            "status": PodStatus.RUNNING,
            "restarts": 0,
            "memory_limit_mb": 256,
            "memory_usage_percent": 40,
            "cpu_usage_percent": 10
        },
        "related_services": ["kube-apiserver", "kube-scheduler", "cloud-controller-manager"],
        "expected_actions": [
            "Node durumunu ve conditions'ları kontrol et",
            "Kubelet servisini doğrula (systemctl status kubelet)",
            "Node'a SSH ile erişmeyi dene",
            "Pod'ları diğer node'lara yeniden schedule et"
        ],
        "root_cause": "worker-node-02 üzerinde kernel panic oluşmuş. "
                      "VM/fiziksel makine yanıt vermiyor ve kubelet heartbeat gönderemiyor.",
        "optimal_fix": "kubectl drain worker-node-02 --ignore-daemonsets --force --delete-emptydir-data && cloud provider'dan node'u restart et veya yeni node ekle"
    },
    {
        "id": "hpa_thrashing",
        "title": "HPA Thrashing - Rapid Scale Oscillation",
        "category": IncidentCategory.CLUSTER,
        "severity": Severity.MEDIUM,
        "service": "recommendation-service",
        "namespace": "production",
        "description": "recommendation-service HPA her 2 dakikada scale up/down yapıyor. "
                       "CPU metriği threshold etrafında sürekli oynuyor. "
                       "Pod'lar tam warm-up olmadan kill ediliyor, latency spike'lara neden oluyor.",
        "metrics": {
            "scale_events_1h": 28,
            "current_replicas": 5,
            "min_replicas": 2,
            "max_replicas": 10,
            "cpu_target_percent": 70,
            "cpu_actual_percent": 68,
            "avg_pod_lifetime_sec": 120,
            "latency_p99_ms": 3200
        },
        "pod_info": {
            "name": "recommendation-service-2c3d4e5f6-{suffix}",
            "status": PodStatus.RUNNING,
            "restarts": 0,
            "memory_limit_mb": 1024,
            "memory_usage_percent": 60,
            "cpu_usage_percent": 68
        },
        "related_services": ["product-service", "user-behavior-api", "cache-layer"],
        "expected_actions": [
            "HPA events ve scaling geçmişini kontrol et",
            "Stabilization window ayarını incele",
            "CPU target percentage'ı ayarla",
            "Scale-down delay ekle"
        ],
        "root_cause": "HPA stabilizationWindowSeconds değeri 0 olarak ayarlanmış (default). "
                      "Recommendation-service'in bursty traffic pattern'i ile bu ayar sürekli scale tetikliyor.",
        "optimal_fix": "kubectl patch hpa recommendation-service -n production -p '{\"spec\":{\"behavior\":{\"scaleDown\":{\"stabilizationWindowSeconds\":300,\"policies\":[{\"type\":\"Percent\",\"value\":10,\"periodSeconds\":60}]}}}}'"
    },
    {
        "id": "etcd_latency_degradation",
        "title": "ETCD Latency Degradation - Cluster State Store Slow",
        "category": IncidentCategory.CLUSTER,
        "severity": Severity.CRITICAL,
        "service": "etcd",
        "namespace": "kube-system",
        "description": "ETCD cluster latency'si normalin 10 katına çıktı. "
                       "API server yanıt süreleri uzadı, kubectl komutları timeout alıyor. "
                       "Disk fsync süresi artmış, olası storage bottleneck.",
        "metrics": {
            "etcd_apply_latency_ms": 850,
            "normal_apply_latency_ms": 25,
            "disk_fsync_duration_ms": 400,
            "api_server_latency_ms": 5000,
            "leader_changes_1h": 3,
            "db_size_gb": 8,
            "kubectl_timeout_rate_percent": 40
        },
        "pod_info": {
            "name": "etcd-control-plane-01",
            "status": PodStatus.RUNNING,
            "restarts": 0,
            "memory_limit_mb": 2048,
            "memory_usage_percent": 75,
            "cpu_usage_percent": 55
        },
        "related_services": ["kube-apiserver", "kube-controller-manager", "kube-scheduler"],
        "expected_actions": [
            "ETCD metriklerini kontrol et (etcdctl endpoint status)",
            "Disk I/O performansını doğrula",
            "ETCD compaction ve defragmentation çalıştır",
            "Leader election geçmişini kontrol et"
        ],
        "root_cause": "ETCD veritabanı boyutu 8GB'a ulaşmış ve auto-compaction devre dışı bırakılmış. "
                      "Büyük DB ile disk fsync süreleri artıyor ve leader election instability oluşuyor.",
        "optimal_fix": "etcdctl defrag --cluster && etcdctl compact $(etcdctl endpoint status -w json | jq '.[0].Status.header.revision')"
    },
    {
        "id": "failed_rolling_update",
        "title": "Failed Rolling Update - Deployment Stuck",
        "category": IncidentCategory.CLUSTER,
        "severity": Severity.HIGH,
        "service": "user-profile-service",
        "namespace": "production",
        "description": "user-profile-service rolling update takıldı. "
                       "Yeni pod'lar readiness probe'u geçemiyor. "
                       "maxUnavailable=1 olduğu için eski pod'lar hâlâ çalışıyor "
                       "ama trafik yeni ve eski pod'lar arasında dengesiz dağılıyor.",
        "metrics": {
            "rollout_progress_percent": 40,
            "new_pods_ready": 2,
            "new_pods_total": 5,
            "old_pods_running": 3,
            "readiness_probe_failures": 15,
            "rollout_stuck_min": 12,
            "error_rate_percent": 22
        },
        "pod_info": {
            "name": "user-profile-service-v2-8a9b0c1d-{suffix}",
            "status": PodStatus.NOT_READY,
            "restarts": 0,
            "memory_limit_mb": 512,
            "memory_usage_percent": 45,
            "cpu_usage_percent": 20
        },
        "related_services": ["user-db", "avatar-service", "preference-service"],
        "expected_actions": [
            "Rollout status kontrol et",
            "Yeni pod'ların neden ready olmadığını belirle",
            "Pod loglarını ve events'leri incele",
            "Rollback veya fix and continue kararı ver"
        ],
        "root_cause": "Yeni versiyon bir veritabanı migration script'i çalıştırıyor ama migration "
                      "DB schema lock nedeniyle timeout oluyor. Pod ready olmuyor.",
        "optimal_fix": "kubectl rollout undo deployment/user-profile-service -n production && migration'ı ayrı job olarak çalıştır"
    },

    # ──────────────────────────────────────
    # BİLİNMEYEN / KARMAŞIK SENARYOLAR
    # (Rule-based runbook'ta YOK — LLM avantajını gösterir)
    # ──────────────────────────────────────
    {
        "id": "unknown_memory_pattern",
        "title": "Unknown Anomaly - Unusual Memory Allocation Pattern",
        "category": IncidentCategory.CLUSTER,
        "severity": Severity.HIGH,
        "service": "ml-inference-service",
        "namespace": "production",
        "description": "ml-inference-service pod'larında garip bir memory pattern tespit edildi. "
                       "Memory kullanımı sabit artmıyor ama her 7 dakikada bir ani 200MB spike yapıp geri düşüyor. "
                       "OOM yok, restart yok ama latency spike'lar bu pattern ile korele. "
                       "Daha önce görülmemiş bir davranış.",
        "metrics": {
            "memory_spike_interval_sec": 420,
            "memory_spike_size_mb": 200,
            "baseline_memory_mb": 350,
            "peak_memory_mb": 550,
            "memory_limit_mb": 1024,
            "latency_during_spike_ms": 2800,
            "normal_latency_ms": 150,
            "gc_pause_during_spike_ms": 800,
            "model_reload_events_1h": 8
        },
        "pod_info": {
            "name": "ml-inference-service-7x8y9z0a-{suffix}",
            "status": PodStatus.RUNNING,
            "restarts": 0,
            "memory_limit_mb": 1024,
            "memory_usage_percent": 54,
            "cpu_usage_percent": 72
        },
        "related_services": ["model-registry", "feature-store", "prediction-api"],
        "expected_actions": [
            "Memory profiling yap",
            "GC loglarını ve model reload pattern'ini incele",
            "Cron veya scheduled task kontrol et",
            "Model caching stratejisini değerlendir"
        ],
        "root_cause": "ML model hot-reload mekanizması her 7 dakikada model registry'den yeni model weights kontrol ediyor. "
                      "Model değişmemiş olsa bile weights'i memory'ye yükleyip sonra discard ediyor, bu da GC pressure yaratıyor.",
        "optimal_fix": "Model reload'u conditional yap: sadece version hash değiştiğinde reload et, aksi halde cache'deki modeli kullan"
    },
    {
        "id": "multi_service_cascade_unknown",
        "title": "Multi-Service Cascade - Correlated Failures Across Namespaces",
        "category": IncidentCategory.CLUSTER,
        "severity": Severity.CRITICAL,
        "service": "multiple",
        "namespace": "production",
        "description": "Birden fazla ilişkisiz serviste eş zamanlı hatalar oluşuyor. "
                       "payment-service (production), monitoring-agent (monitoring) ve ci-runner (ci-cd) "
                       "aynı anda sorun yaşıyor. Ortak bağımlılıkları yok gibi görünüyor. "
                       "Her servisin hatası farklı: biri timeout, biri DNS, biri disk. "
                       "Standart runbook'lar bu çoklu hata pattern'ini kapsamıyor.",
        "metrics": {
            "affected_namespaces": 3,
            "affected_services": 5,
            "payment_error_rate_percent": 30,
            "monitoring_gap_min": 8,
            "ci_pipeline_failures": 12,
            "node_count_healthy": 2,
            "node_count_total": 4,
            "shared_storage_latency_ms": 4500,
            "normal_storage_latency_ms": 10
        },
        "pod_info": {
            "name": "payment-service-cascade-{suffix}",
            "status": PodStatus.RUNNING,
            "restarts": 3,
            "memory_limit_mb": 512,
            "memory_usage_percent": 65,
            "cpu_usage_percent": 40
        },
        "related_services": ["payment-service", "monitoring-agent", "ci-runner", "shared-nfs", "csi-driver"],
        "expected_actions": [
            "Ortak altyapı bileşenlerini belirle",
            "Shared storage durumunu kontrol et",
            "Network fabric sağlığını doğrula",
            "Node-level sorunları araştır"
        ],
        "root_cause": "Tüm servislerin ortak noktası shared NFS storage. NFS server'ın disk'i dolmuş ve "
                      "tüm mount point'ler yavaşlamış. Her servis farklı semptom gösteriyor ama kök neden aynı.",
        "optimal_fix": "NFS server disk temizliği ve geçici olarak etkilenen pod'ları local storage'a taşı"
    },
]


# ═══════════════════════════════════════════════════════
# Cloud Simulator
# ═══════════════════════════════════════════════════════

class CloudSimulator:
    """Kubernetes cluster simülatörü."""

    def __init__(self):
        self.incidents = INCIDENT_SCENARIOS
        self.active_incidents = []
        self.resolved_incidents = []
        self.cluster_state = self._init_cluster()

    def _init_cluster(self):
        return {
            "nodes": [
                {"name": "worker-node-01", "status": "Ready", "cpu_percent": 45, "memory_percent": 62},
                {"name": "worker-node-02", "status": "Ready", "cpu_percent": 38, "memory_percent": 55},
                {"name": "worker-node-03", "status": "Ready", "cpu_percent": 72, "memory_percent": 78},
                {"name": "control-plane-01", "status": "Ready", "cpu_percent": 22, "memory_percent": 40},
            ],
            "namespaces": ["production", "staging", "monitoring", "ingress", "kube-system"],
            "total_pods": 67,
            "healthy_pods": 62,
            "services": 20,
            "deployments": 24
        }

    def generate_alert(self, scenario_id: str = None) -> Alert:
        """Belirli veya rastgele bir senaryo için alert üretir. Metrikler her seferinde dinamik olarak değişir."""
        if scenario_id:
            scenario = next((s for s in self.incidents if s["id"] == scenario_id), None)
            if not scenario:
                raise ValueError(f"Senaryo bulunamadı: {scenario_id}")
        else:
            scenario = random.choice(self.incidents)

        randomized_metrics = self._randomize_metrics(scenario["metrics"])
        randomized_pod_info = self._randomize_pod_info(scenario.get("pod_info"))

        alert = Alert(
            id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
            timestamp=datetime.now().isoformat(),
            severity=scenario["severity"].value,
            title=scenario["title"],
            description=scenario["description"],
            source_service=scenario["service"],
            namespace=scenario["namespace"],
            metrics=randomized_metrics,
            pod_info=randomized_pod_info,
            related_services=scenario.get("related_services", [])
        )
        self.active_incidents.append({
            "alert": alert.to_dict(),
            "scenario": scenario
        })
        return alert

    def get_scenario_details(self, scenario_id: str) -> dict:
        scenario = next((s for s in self.incidents if s["id"] == scenario_id), None)
        return scenario

    def list_scenarios(self) -> list:
        return [
            {
                "id": s["id"],
                "title": s["title"],
                "severity": s["severity"].value,
                "service": s["service"],
                "category": s["category"].value
            }
            for s in self.incidents
        ]

    # ─── Dinamik Metrik Randomizasyonu ───

    def _randomize_metrics(self, base_metrics: dict) -> dict:
        """Her tetiklemede farklı ama gerçekçi metrik değerleri üretir."""
        result = {}
        for key, val in base_metrics.items():
            if isinstance(val, bool):
                result[key] = val
            elif isinstance(val, int):
                if val == 0:
                    result[key] = 0
                else:
                    low = max(1, int(val * random.uniform(0.65, 0.85)))
                    high = max(low + 1, int(val * random.uniform(1.15, 1.4)))
                    result[key] = random.randint(low, high)
                    if "percent" in key:
                        result[key] = min(100, result[key])
            elif isinstance(val, float):
                factor = random.uniform(0.7, 1.35)
                result[key] = round(val * factor, 1)
                if "percent" in key:
                    result[key] = min(100.0, result[key])
            elif isinstance(val, list):
                result[key] = val
            elif isinstance(val, str):
                result[key] = val
            else:
                result[key] = val
        return result

    def _randomize_pod_info(self, base_pod: dict) -> Optional[dict]:
        """Pod adını ve restart sayısını rastgele değiştirir."""
        if not base_pod:
            return None
        pod = dict(base_pod)
        suffix = uuid.uuid4().hex[:5]
        pod["name"] = pod["name"].replace("{suffix}", suffix).replace("{numeric_suffix}", str(random.randint(0, 4)))
        if pod.get("restarts", 0) > 0:
            base = pod["restarts"]
            pod["restarts"] = random.randint(max(1, base - 5), base + 8)
        if pod.get("memory_usage_percent", 0) > 0:
            pod["memory_usage_percent"] = min(100, max(5, pod["memory_usage_percent"] + random.randint(-10, 10)))
        if pod.get("cpu_usage_percent", 0) > 0:
            pod["cpu_usage_percent"] = min(100, max(5, pod["cpu_usage_percent"] + random.randint(-10, 10)))
        return pod

    # ─── kubectl Simülasyonları ───

    def simulate_kubectl_get_pods(self, namespace: str = "production") -> str:
        active = self.active_incidents[-1] if self.active_incidents else None
        pods = []
        if active:
            sc = active["scenario"]
            pod_info = sc.get("pod_info", {})
            name = pod_info.get("name", "unknown").replace("{suffix}", uuid.uuid4().hex[:5]).replace("{numeric_suffix}", "2")
            pods.append(
                f"{name}   1/1   {pod_info.get('status', 'Running')}   "
                f"{pod_info.get('restarts', 0)}   2d"
            )
        healthy_pods = [
            "frontend-app-5d6e7f8g9-a1b2c   1/1   Running   0   5d",
            "redis-cache-0                   1/1   Running   0   12d",
            "nginx-ingress-4c5d6e7f8-h9i0j   1/1   Running   0   30d",
        ]
        pods.extend(healthy_pods)
        header = "NAME                                READY   STATUS             RESTARTS   AGE"
        return header + "\n" + "\n".join(pods)

    def simulate_kubectl_logs(self, pod_name: str) -> str:
        active = self.active_incidents[-1] if self.active_incidents else None
        if not active:
            return "No recent logs available."

        sc = active["scenario"]
        sid = sc["id"]
        ts = datetime.now().strftime("%Y-%m-%dT%H:%M:")

        log_templates = {
            "oom_kill_memory_leak": [
                f"{ts}32Z ERROR [payment-handler] java.lang.OutOfMemoryError: Java heap space",
                f"{ts}32Z ERROR   at com.payment.ConnectionPool.createConnection(ConnectionPool.java:142)",
                f"{ts}32Z ERROR   at com.payment.RequestHandler.processPayment(RequestHandler.java:89)",
                f"{ts}33Z WARN  [gc-monitor] GC overhead limit exceeded. Heap: 498MB/512MB",
                f"{ts}34Z ERROR [connection-pool] Active connections: {random.randint(400,900)} (expected max: 50)",
                f"{ts}34Z FATAL [main] Container killed by OOM: memory usage 524288000 > limit 536870912",
            ],
            "crash_loop_backoff": [
                f"{ts}10Z INFO  [main] Starting notification-service v3.1.0...",
                f"{ts}10Z INFO  [config] Loading configuration from ConfigMap...",
                f"{ts}11Z ERROR [config] Required environment variable SMTP_HOST is not set!",
                f"{ts}11Z ERROR [config] Config validation failed: missing 1 required variable(s)",
                f"{ts}11Z FATAL [main] Application startup aborted. Exiting with code 1.",
                f"{ts}11Z INFO  [main] Process exited. Restart count: {random.randint(15,35)}",
            ],
            "image_pull_backoff": [
                f"{ts}05Z WARN  [kubelet] Failed to pull image \"registry.example.com/catalog-service:v2.5.0\"",
                f"{ts}05Z ERROR [kubelet] Error response from daemon: unauthorized: authentication required",
                f"{ts}06Z WARN  [kubelet] Back-off pulling image, retrying in 10s...",
                f"{ts}16Z ERROR [kubelet] imagePullSecret 'regcred' token expired at 2026-03-24T08:00:00Z",
                f"{ts}17Z WARN  [kubelet] Container image pull failed {random.randint(8,20)} times",
            ],
            "liveness_probe_failure": [
                f"{ts}20Z WARN  [health] /health endpoint took 6200ms to respond (timeout: 5000ms)",
                f"{ts}20Z ERROR [elasticsearch-client] Connection to ES cluster timed out after 5000ms",
                f"{ts}21Z WARN  [kubelet] Liveness probe failed: HTTP probe failed with status 503",
                f"{ts}21Z INFO  [kubelet] Container search-service failed liveness probe, will be restarted",
                f"{ts}22Z WARN  [health] Upstream dependency check failed: elasticsearch-cluster (status: red)",
                f"{ts}22Z INFO  [main] Received SIGTERM. Graceful shutdown initiated...",
            ],
            "cascading_latency": [
                f"{ts}15Z WARN  [db-pool] Connection pool exhausted. Active: 100/100, Waiting: {random.randint(150,400)}",
                f"{ts}15Z ERROR [query-executor] Query timeout after 45000ms: SELECT * FROM analytics_raw...",
                f"{ts}16Z WARN  [order-handler] Downstream timeout: inventory-service (5000ms)",
                f"{ts}17Z ERROR [circuit-breaker] OPEN for shipping-service after 10 consecutive failures",
                f"{ts}18Z WARN  [hpa] Cannot scale: already at max replicas (10/10)",
            ],
            "dns_resolution_failure": [
                f"{ts}00Z ERROR [coredns] plugin/forward: no healthy upstreams",
                f"{ts}00Z WARN  [coredns] Failed to resolve: order-service.production.svc.cluster.local NXDOMAIN",
                f"{ts}01Z ERROR [coredns] Memory usage at 95%, cache eviction rate spiking",
                f"{ts}01Z WARN  [coredns] query rate: {random.randint(8000,15000)} qps (capacity: 5000 qps)",
                f"{ts}02Z ERROR [app] java.net.UnknownHostException: payment-service.production.svc.cluster.local",
            ],
            "ingress_backend_502": [
                f"{ts}30Z ERROR [nginx] upstream prematurely closed connection while reading response header",
                f"{ts}30Z WARN  [nginx] *{random.randint(1000,9999)} upstream timed out (110: Connection timed out)",
                f"{ts}31Z ERROR [nginx] no live upstreams for backend checkout-service-production",
                f"{ts}31Z INFO  [nginx] Endpoints for checkout-service: 2/6 healthy",
                f"{ts}32Z WARN  [nginx] 502 Bad Gateway rate: 15% of total requests",
            ],
            "node_pressure": [
                f"{ts}25Z WARN  [kubelet] Node worker-node-03: DiskPressure condition detected",
                f"{ts}25Z WARN  [elasticsearch] Disk watermark [flood] exceeded on node data-2: {random.randint(85,95)}% used",
                f"{ts}26Z ERROR [fluentd] Buffer overflow: dropping {random.randint(1500,4000)} logs/sec",
                f"{ts}26Z WARN  [kubelet] Evicting pods due to DiskPressure",
            ],
            "pvc_mount_failure": [
                f"{ts}40Z WARN  [kubelet] Unable to attach or mount volumes: timeout expired waiting for volumes to attach",
                f"{ts}40Z ERROR [provisioner] Failed to provision volume: googleapi: Error 403: Quota 'DISKS_TOTAL_GB' exceeded",
                f"{ts}41Z WARN  [scheduler] 0/4 nodes are available: 3 pod has unbound immediate PersistentVolumeClaims",
                f"{ts}42Z ERROR [provisioner] Retry attempt {random.randint(8,20)}: still unable to provision PV",
            ],
            "persistent_volume_full": [
                f"{ts}15Z ERROR [postgresql] PANIC: could not write to file \"pg_wal/xlogtemp.{random.randint(1000,9999)}\": No space left on device",
                f"{ts}15Z WARN  [postgresql] WAL directory size: 45GB, Total disk: 50GB",
                f"{ts}16Z ERROR [postgresql] database is not accepting write commands — disk full",
                f"{ts}16Z WARN  [postgresql] Inactive replication slot 'replica_old_slot' preventing WAL cleanup",
                f"{ts}17Z ERROR [pgbouncer] All {random.randint(5,12)} downstream services reporting write failures",
            ],
            "security_breach_attempt": [
                f"{ts}30Z ALERT [falco] Suspicious outbound connection to 185.x.x.x:4444",
                f"{ts}30Z ALERT [falco] Process 'curl' downloading binary from suspicious-domain.com",
                f"{ts}31Z WARN  [auth-monitor] Brute force detected: {random.randint(300,600)} failed auth/min (normal: 50)",
                f"{ts}31Z ERROR [vuln-scanner] CVE-2026-1234 (CRITICAL) found in openssl 3.0.2",
                f"{ts}32Z ALERT [network-policy] Anomalous egress: {random.randint(50,120)} MB/s (normal: 2 MB/s)",
            ],
            "rbac_permission_denied": [
                f"{ts}10Z ERROR [argocd] Failed to create deployment: deployments.apps is forbidden: User \"system:serviceaccount:argocd:argocd-application-controller\" cannot create resource \"deployments\" in API group \"apps\" in namespace \"production\"",
                f"{ts}10Z WARN  [argocd] Sync failed for application 'payment-service': permission denied",
                f"{ts}11Z ERROR [argocd] {random.randint(3,8)} applications stuck in OutOfSync state",
                f"{ts}12Z WARN  [pipeline] CI/CD pipeline 'deploy-prod' failed at stage 'kubectl-apply'",
            ],
            "secret_leak_detection": [
                f"{ts}00Z DEBUG [auth-service] DB Connection: postgresql://admin:s3cr3t_p@ssw0rd@db.internal:5432/users",
                f"{ts}00Z DEBUG [auth-service] Redis auth: redis://:r3d1s_t0ken@redis.internal:6379/0",
                f"{ts}01Z ALERT [log-scanner] Detected {random.randint(500,1200)} log entries containing potential credentials",
                f"{ts}01Z ALERT [log-scanner] Secrets found: DB_PASSWORD, REDIS_AUTH_TOKEN, JWT_SIGNING_KEY",
                f"{ts}02Z WARN  [log-aggregator] {random.randint(500,1200)} entries with secrets already shipped to external ELK",
            ],
            "config_drift_ssl": [
                f"{ts}10Z ERROR [cert-manager] Failed to present DNS01 challenge for api.example.com",
                f"{ts}10Z ERROR [cert-manager] dns01: provider error: 403 Forbidden - invalid API key",
                f"{ts}11Z WARN  [cert-manager] Certificate expires in {random.randint(1,4)}h. Renewal attempt 3/3 failed",
                f"{ts}11Z INFO  [cert-manager] Next retry in 30 minutes",
            ],
            "configmap_not_found": [
                f"{ts}20Z ERROR [kubelet] Error: configmap \"billing-config\" not found",
                f"{ts}20Z WARN  [scheduler] pod billing-service-9h0i1j2k3-x4y5z is stuck in Pending: configmap not found",
                f"{ts}21Z ERROR [kubelet] MountVolume.SetUp failed for volume \"config-vol\": configmap \"billing-config\" not found",
                f"{ts}22Z WARN  [deployment-controller] Deployment billing-service cannot scale: {random.randint(1,3)} pods stuck in Pending",
            ],
            "resource_quota_exceeded": [
                f"{ts}35Z ERROR [scheduler] pods \"data-pipeline-runner-1a2b3c4d-x5y6z\" is forbidden: exceeded quota: production-quota",
                f"{ts}35Z WARN  [scheduler] requested: cpu=2, memory=2Gi — used: cpu=32/32, memory=58Gi/64Gi",
                f"{ts}36Z ERROR [hpa] unable to scale data-pipeline: failed to create pod: quota exceeded",
                f"{ts}36Z WARN  [quota-controller] {random.randint(15,30)} completed/failed pods consuming quota resources",
            ],
            "node_not_ready": [
                f"{ts}00Z WARN  [node-controller] Node worker-node-02 condition Ready: Unknown (Kubelet stopped posting node status)",
                f"{ts}01Z WARN  [node-controller] Adding taint {{NoSchedule, NoExecute}} to node worker-node-02",
                f"{ts}02Z INFO  [node-controller] Starting pod eviction for node worker-node-02 ({random.randint(8,15)} pods)",
                f"{ts}03Z ERROR [scheduler] 0/{random.randint(2,3)} nodes available for rescheduling evicted pods — resource pressure",
                f"{ts}04Z WARN  [cloud-controller] VM instance worker-node-02 health check: UNREACHABLE",
            ],
            "hpa_thrashing": [
                f"{ts}00Z INFO  [hpa] New size: 8; reason: cpu resource utilization above target (76% > 70%)",
                f"{ts}02Z INFO  [hpa] New size: 4; reason: cpu resource utilization below target (52% < 70%)",
                f"{ts}04Z INFO  [hpa] New size: 7; reason: cpu resource utilization above target (73% > 70%)",
                f"{ts}06Z INFO  [hpa] New size: 3; reason: cpu resource utilization below target (48% < 70%)",
                f"{ts}07Z WARN  [hpa] {random.randint(20,35)} scale events in last hour — possible thrashing detected",
                f"{ts}08Z WARN  [app] Connection pool exhausted during scale-down — 500 errors spiking",
            ],
            "etcd_latency_degradation": [
                f"{ts}10Z WARN  [etcd] apply request took too long [{random.randint(600,1200)}ms]",
                f"{ts}10Z WARN  [etcd] disk fsync duration: {random.randint(300,600)}ms (threshold: 100ms)",
                f"{ts}11Z ERROR [etcd] leader changed from node-1 to node-3 (3rd change in 1h)",
                f"{ts}12Z WARN  [apiserver] request timeout: GET /api/v1/namespaces/production/pods — etcd response slow",
                f"{ts}12Z ERROR [etcd] database size: 8.2GB, approaching max (10GB). Compaction overdue.",
            ],
            "failed_rolling_update": [
                f"{ts}50Z INFO  [deployment-controller] Scaled up replica set user-profile-service-v2 to 5",
                f"{ts}51Z WARN  [deployment-controller] Deployment user-profile-service has {random.randint(2,3)} ready, 5 desired — stuck",
                f"{ts}52Z ERROR [init-container] Migration script timeout after 60s: ALTER TABLE users ADD COLUMN preferences JSONB",
                f"{ts}52Z ERROR [init-container] Cannot acquire lock: another migration is running",
                f"{ts}53Z WARN  [deployment-controller] ProgressDeadlineExceeded: deployment has not progressed in 10m",
            ],
            "unknown_memory_pattern": [
                f"{ts}00Z INFO  [model-loader] Loading model weights from model-registry:8080/models/v47",
                f"{ts}01Z INFO  [model-loader] Downloaded model weights: 198MB in 3.2s",
                f"{ts}02Z WARN  [gc-monitor] Major GC triggered: pause={random.randint(600,1200)}ms, freed=190MB",
                f"{ts}03Z INFO  [model-loader] Model checksum matches current — no update needed, discarding",
                f"{ts}04Z WARN  [metrics] Latency spike detected during GC: p99={random.randint(2000,3500)}ms",
                f"{ts}05Z INFO  [scheduler] Next model check in 420 seconds",
                f"{ts}10Z WARN  [heap-monitor] Sawtooth memory pattern detected: baseline=350MB, peak=550MB, period=~7min",
            ],
            "multi_service_cascade_unknown": [
                f"{ts}00Z ERROR [payment-service] java.net.SocketTimeoutException: Read timed out after 30000ms",
                f"{ts}01Z ERROR [monitoring-agent] Failed to write metrics: disk I/O timeout on /data/prometheus",
                f"{ts}01Z WARN  [ci-runner] Build artifact upload failed: NFS write error - Stale file handle",
                f"{ts}02Z WARN  [node-exporter] worker-node-01: disk await={random.randint(800,2000)}ms (normal: 5ms)",
                f"{ts}02Z WARN  [node-exporter] worker-node-03: disk await={random.randint(500,1500)}ms (normal: 5ms)",
                f"{ts}03Z ERROR [nfs-client] NFS server 10.0.1.50: RPC timeout, retrying...",
                f"{ts}03Z ALERT [storage] NFS server disk usage: 99.8% — {random.randint(100,300)}MB free of 2TB",
                f"{ts}04Z WARN  [kubelet] {random.randint(8,15)} pods with NFS mounts reporting I/O errors across 3 namespaces",
            ],
        }

        logs = log_templates.get(sid, ["No specific logs for this scenario."])
        return "\n".join(logs)

    def simulate_remediation_result(self, scenario_id: str, action: str) -> dict:
        scenario = next((s for s in self.incidents if s["id"] == scenario_id), None)
        if not scenario:
            return {"success": False, "message": "Senaryo bulunamadı"}
        return {
            "success": True,
            "action_taken": action,
            "before_metrics": scenario["metrics"],
            "after_metrics": self._simulate_fixed_metrics(scenario["metrics"]),
            "root_cause_identified": scenario["root_cause"],
            "optimal_fix": scenario["optimal_fix"],
            "mttr_seconds": random.randint(15, 90),
            "timestamp": datetime.now().isoformat()
        }

    def _simulate_fixed_metrics(self, original: dict) -> dict:
        fixed = {}
        for key, val in original.items():
            if isinstance(val, (int, float)):
                if "error" in key or "failure" in key:
                    fixed[key] = max(0, val * 0.05)
                elif "latency" in key:
                    fixed[key] = max(50, val * 0.1)
                elif "usage" in key or "percent" in key:
                    fixed[key] = min(100, max(10, val * 0.5))
                else:
                    fixed[key] = val
            else:
                fixed[key] = val
        return fixed
