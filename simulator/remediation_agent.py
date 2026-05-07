"""
LLM-Based Remediation Agent
ReAct (Reasoning + Acting) pattern ile çalışan remediation motoru.
Gerçek LLM olmadan da çalışabilen simülasyon modu içerir.
"""
import json
import time
import uuid
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional


# ─── Bilgi Tabanı (Knowledge Base / Runbook'lar) ───
RUNBOOK_KNOWLEDGE = {
    "oom_kill": {
        "symptoms": ["OOMKilled", "OutOfMemoryError", "memory limit exceeded", "heap space"],
        "diagnosis_steps": [
            "Pod loglarını kontrol et → memory error pattern'lerini ara",
            "kubectl top pod ile memory kullanımını doğrula",
            "Son deployment değişikliklerini kontrol et (kubectl rollout history)",
            "Memory leak olup olmadığını belirle (artan trend vs ani spike)"
        ],
        "remediation_options": [
            {
                "action": "Deployment rollback (memory leak durumunda)",
                "command": "kubectl rollout undo deployment/{service} -n {namespace}",
                "risk": "low",
                "confidence": 0.85,
                "description": "Son çalışan sürüme geri dön"
            },
            {
                "action": "Memory limit artırma (gerçek ihtiyaç artışı durumunda)",
                "command": "kubectl patch deployment/{service} -n {namespace} -p '{{\"spec\":{{\"template\":{{\"spec\":{{\"containers\":[{{\"name\":\"{service}\",\"resources\":{{\"limits\":{{\"memory\":\"1Gi\"}}}}}}]}}}}}}}}}'",
                "risk": "medium",
                "confidence": 0.70,
                "description": "Memory limitini 2x artır"
            },
            {
                "action": "Pod restart (geçici çözüm)",
                "command": "kubectl rollout restart deployment/{service} -n {namespace}",
                "risk": "low",
                "confidence": 0.60,
                "description": "Tüm pod'ları graceful restart et"
            }
        ]
    },
    "high_latency": {
        "symptoms": ["latency spike", "timeout", "connection pool exhausted", "slow query"],
        "diagnosis_steps": [
            "Upstream ve downstream servis durumlarını kontrol et",
            "DB connection pool metriklerini incele",
            "Slow query loglarını analiz et",
            "HPA durumunu ve resource kullanımını kontrol et"
        ],
        "remediation_options": [
            {
                "action": "Sorunlu cronjob/query'yi durdur",
                "command": "kubectl delete cronjob/{culprit} -n {namespace}",
                "risk": "low",
                "confidence": 0.90,
                "description": "Resource tüketen işlemi sonlandır"
            },
            {
                "action": "Pod sayısını artır (horizontal scale)",
                "command": "kubectl scale deployment/{service} --replicas={target_replicas} -n {namespace}",
                "risk": "low",
                "confidence": 0.75,
                "description": "Replica sayısını artırarak yükü dağıt"
            },
            {
                "action": "Circuit breaker aktif et",
                "command": "kubectl patch configmap/{service}-config -n {namespace} -p '{{\"data\":{{\"CIRCUIT_BREAKER_ENABLED\":\"true\"}}}}'",
                "risk": "medium",
                "confidence": 0.80,
                "description": "Downstream bağımlılık hatalarının yayılmasını engelle"
            }
        ]
    },
    "ssl_cert": {
        "symptoms": ["certificate expiry", "SSL", "TLS", "cert-manager", "renewal failed"],
        "diagnosis_steps": [
            "cert-manager loglarını kontrol et",
            "DNS provider erişimini doğrula",
            "Mevcut sertifika süresini kontrol et",
            "Secret durumlarını kontrol et"
        ],
        "remediation_options": [
            {
                "action": "DNS credentials secret güncelle",
                "command": "kubectl create secret generic dns-credentials -n cert-manager --from-literal=api-key=ROTATED_KEY --dry-run=client -o yaml | kubectl apply -f -",
                "risk": "low",
                "confidence": 0.90,
                "description": "Rotate edilmiş API key'i güncelle"
            },
            {
                "action": "Manuel sertifika yenileme tetikle",
                "command": "kubectl delete certificate {cert_name} -n {namespace} && kubectl apply -f certificate.yaml",
                "risk": "medium",
                "confidence": 0.80,
                "description": "Sertifika kaynağını yeniden oluştur"
            }
        ]
    },
    "disk_pressure": {
        "symptoms": ["DiskPressure", "disk I/O", "disk watermark", "buffer overflow"],
        "diagnosis_steps": [
            "Node disk kullanımını kontrol et (df -h)",
            "En çok disk kullanan pod'ları belirle",
            "Log retention policy'yi kontrol et",
            "Eski verileri temizleme olasılığını değerlendir"
        ],
        "remediation_options": [
            {
                "action": "Eski index/log'ları temizle",
                "command": "curator_cli delete_indices --older-than 30 --time-unit days",
                "risk": "medium",
                "confidence": 0.85,
                "description": "30 günden eski index'leri sil"
            },
            {
                "action": "Pod'ları diğer node'lara taşı",
                "command": "kubectl drain {node} --ignore-daemonsets --delete-emptydir-data",
                "risk": "high",
                "confidence": 0.70,
                "description": "Node'u boşalt ve pod'ları redistribute et"
            }
        ]
    },
    "security_incident": {
        "symptoms": ["suspicious", "crypto mining", "CVE", "brute force", "anomalous egress"],
        "diagnosis_steps": [
            "Pod'u hemen izole et (network policy)",
            "Forensic analiz için pod snapshotı al",
            "Etkilenen secret'ları belirle",
            "Saldırı vektörünü tespit et"
        ],
        "remediation_options": [
            {
                "action": "Pod network izolasyonu (ACİL)",
                "command": "kubectl apply -f deny-all-egress-policy.yaml -n {namespace}",
                "risk": "low",
                "confidence": 0.95,
                "description": "Pod'un tüm outbound trafiğini kes"
            },
            {
                "action": "Güvenli image ile redeploy",
                "command": "kubectl set image deployment/{service} {service}={service}:patched -n {namespace}",
                "risk": "medium",
                "confidence": 0.90,
                "description": "Yamalarınmış container image ile yeniden deploy et"
            },
            {
                "action": "Secret rotation başlat",
                "command": "kubectl rollout restart deployment --all -n {namespace}",
                "risk": "high",
                "confidence": 0.85,
                "description": "Tüm secret'ları yenile ve servisları restart et"
            }
        ]
    },
    "crash_loop": {
        "symptoms": ["CrashLoopBackOff", "exit code", "missing env", "startup failure", "config validation"],
        "diagnosis_steps": [
            "Pod events'lerini kontrol et (kubectl describe pod)",
            "Container loglarını incele — son exit nedenini bul",
            "ConfigMap ve Secret bağımlılıklarını doğrula",
            "Son deployment değişikliklerini karşılaştır (rollout history)"
        ],
        "remediation_options": [
            {
                "action": "Eksik ConfigMap/env variable'ı düzelt",
                "command": "kubectl patch configmap {service}-config -n {namespace} --type merge -p '{{\"data\":{{\"MISSING_KEY\":\"correct_value\"}}}}'",
                "risk": "low",
                "confidence": 0.90,
                "description": "Eksik konfigürasyon değerini ekle"
            },
            {
                "action": "Son çalışan versiyona rollback",
                "command": "kubectl rollout undo deployment/{service} -n {namespace}",
                "risk": "low",
                "confidence": 0.85,
                "description": "Son stabil versiyona geri dön"
            }
        ]
    },
    "image_pull": {
        "symptoms": ["ImagePullBackOff", "ErrImagePull", "unauthorized", "registry auth", "pull failed"],
        "diagnosis_steps": [
            "Pod events ile tam hata mesajını oku",
            "imagePullSecret'ın varlığını ve geçerliliğini doğrula",
            "Image tag'in registry'de mevcut olduğunu kontrol et",
            "Registry erişimini test et (docker login)"
        ],
        "remediation_options": [
            {
                "action": "imagePullSecret'ı yenile",
                "command": "kubectl create secret docker-registry regcred --docker-server=registry.example.com --docker-username=svc --docker-password=$(vault read -field=token secret/registry) -n {namespace} --dry-run=client -o yaml | kubectl apply -f -",
                "risk": "low",
                "confidence": 0.90,
                "description": "Expire olmuş registry kimlik bilgisini güncelle"
            },
            {
                "action": "Image tag'i düzelt ve redeploy",
                "command": "kubectl set image deployment/{service} {service}=registry.example.com/{service}:latest -n {namespace}",
                "risk": "medium",
                "confidence": 0.75,
                "description": "Doğru image tag ile yeniden deploy et"
            }
        ]
    },
    "probe_failure": {
        "symptoms": ["liveness probe failed", "readiness probe", "unhealthy", "probe timeout", "HTTP probe failed"],
        "diagnosis_steps": [
            "Health endpoint'ini manuel test et (kubectl exec + curl)",
            "Probe yapılandırmasını kontrol et (timeout, threshold)",
            "Upstream dependency'lerin sağlığını doğrula",
            "Pod resource kullanımını kontrol et"
        ],
        "remediation_options": [
            {
                "action": "Probe timeout süresini artır",
                "command": "kubectl patch deployment {service} -n {namespace} -p '{{\"spec\":{{\"template\":{{\"spec\":{{\"containers\":[{{\"name\":\"{service}\",\"livenessProbe\":{{\"timeoutSeconds\":15}}}}]}}}}}}}}'",
                "risk": "low",
                "confidence": 0.80,
                "description": "Geçici olarak probe timeout'unu artır"
            },
            {
                "action": "Upstream bağımlılığı düzelt",
                "command": "kubectl rollout restart deployment/elasticsearch-cluster -n {namespace}",
                "risk": "medium",
                "confidence": 0.85,
                "description": "Asıl sorunun kaynağı olan upstream servisi restart et"
            }
        ]
    },
    "dns_failure": {
        "symptoms": ["DNS", "NXDOMAIN", "resolve", "CoreDNS", "UnknownHostException", "name resolution"],
        "diagnosis_steps": [
            "CoreDNS pod'larının durumunu kontrol et",
            "DNS çözümleme testi yap (nslookup, dig)",
            "CoreDNS kaynak kullanımını incele",
            "DNS query rate ve hata oranlarını kontrol et"
        ],
        "remediation_options": [
            {
                "action": "CoreDNS replica sayısını artır",
                "command": "kubectl scale deployment coredns -n kube-system --replicas=5",
                "risk": "low",
                "confidence": 0.85,
                "description": "DNS kapasitesini artırarak yükü dağıt"
            },
            {
                "action": "Sorunlu servisi düzelt (DNS storm kaynağı)",
                "command": "kubectl rollout restart deployment/{service} -n {namespace}",
                "risk": "medium",
                "confidence": 0.80,
                "description": "Aşırı DNS sorgusu yapan servisi restart et"
            }
        ]
    },
    "ingress_error": {
        "symptoms": ["502", "Bad Gateway", "upstream", "backend unavailable", "no live upstreams"],
        "diagnosis_steps": [
            "Ingress controller loglarını kontrol et",
            "Backend endpoint sağlığını doğrula",
            "Readiness probe yapılandırmasını incele",
            "Son deployment değişikliklerini kontrol et"
        ],
        "remediation_options": [
            {
                "action": "Readiness probe initialDelay'i artır",
                "command": "kubectl patch deployment {service} -n {namespace} -p '{{\"spec\":{{\"template\":{{\"spec\":{{\"containers\":[{{\"name\":\"{service}\",\"readinessProbe\":{{\"initialDelaySeconds\":120}}}}]}}}}}}}}'",
                "risk": "low",
                "confidence": 0.85,
                "description": "Pod hazır olmadan trafik almasını engelle"
            },
            {
                "action": "Eski pod'lara rollback",
                "command": "kubectl rollout undo deployment/{service} -n {namespace}",
                "risk": "low",
                "confidence": 0.80,
                "description": "Çalışan eski versiyona geri dön"
            }
        ]
    },
    "pvc_failure": {
        "symptoms": ["PVC", "mount", "provision", "StorageClass", "unbound", "volume attach"],
        "diagnosis_steps": [
            "PVC durumunu ve events'lerini kontrol et",
            "StorageClass provisioner loglarını incele",
            "Cloud provider disk quota'sını doğrula",
            "Kullanılmayan PV/PVC'leri listele"
        ],
        "remediation_options": [
            {
                "action": "Kullanılmayan PV'leri temizle",
                "command": "kubectl get pv --no-headers | grep Released | awk '{{print $1}}' | xargs kubectl delete pv",
                "risk": "medium",
                "confidence": 0.85,
                "description": "Released durumundaki PV'leri silerek quota'yı boşalt"
            },
            {
                "action": "Cloud provider quota artır",
                "command": "gcloud compute project-info add-metadata --metadata=DISKS_TOTAL_GB=2000",
                "risk": "low",
                "confidence": 0.75,
                "description": "Disk quota limitini artır"
            }
        ]
    },
    "volume_full": {
        "symptoms": ["disk full", "read-only", "WAL", "no space left", "write blocked"],
        "diagnosis_steps": [
            "Disk kullanımını kontrol et (df -h)",
            "WAL dosya boyutlarını incele",
            "Replication slot durumlarını kontrol et",
            "Gereksiz veri ve log dosyalarını belirle"
        ],
        "remediation_options": [
            {
                "action": "Inactive replication slot'u kaldır",
                "command": "kubectl exec -n {namespace} {service}-0 -- psql -c \"SELECT pg_drop_replication_slot('replica_old_slot');\"",
                "risk": "medium",
                "confidence": 0.90,
                "description": "WAL birikimini engelleyen slot'u kaldır"
            },
            {
                "action": "PV boyutunu genişlet",
                "command": "kubectl patch pvc {service}-data -n {namespace} -p '{{\"spec\":{{\"resources\":{{\"requests\":{{\"storage\":\"100Gi\"}}}}}}}}'",
                "risk": "low",
                "confidence": 0.80,
                "description": "Disk kapasitesini artır"
            }
        ]
    },
    "rbac_issue": {
        "symptoms": ["Forbidden", "RBAC", "permission denied", "unauthorized", "cannot create", "cannot update"],
        "diagnosis_steps": [
            "Service account izinlerini kontrol et (kubectl auth can-i)",
            "ClusterRole ve RoleBinding'i incele",
            "Son RBAC değişikliklerini audit et",
            "Etkilenen kaynakları ve API gruplarını belirle"
        ],
        "remediation_options": [
            {
                "action": "Eksik RBAC iznini ekle",
                "command": "kubectl patch clusterrole cicd-deployer --type=json -p='[{{\"op\":\"add\",\"path\":\"/rules/-\",\"value\":{{\"apiGroups\":[\"apps\"],\"resources\":[\"deployments\"],\"verbs\":[\"create\",\"update\",\"patch\"]}}}}]'",
                "risk": "low",
                "confidence": 0.90,
                "description": "Kaldırılan izni geri ekle"
            },
            {
                "action": "ClusterRole'u önceki durumuna geri al",
                "command": "kubectl apply -f backup/clusterrole-cicd-deployer.yaml",
                "risk": "medium",
                "confidence": 0.85,
                "description": "Yedekten geri yükle"
            }
        ]
    },
    "secret_leak": {
        "symptoms": ["secret", "credential", "password", "token", "exposed", "leak", "debug mode"],
        "diagnosis_steps": [
            "Pod log level'ını kontrol et",
            "Log'larda credential pattern'i tara",
            "External log sistemlerine gönderilen veriyi belirle",
            "Etkilenen secret'ları listele"
        ],
        "remediation_options": [
            {
                "action": "Debug mode'u kapat ve credential'ları rotate et",
                "command": "kubectl set env deployment/{service} LOG_LEVEL=warn -n {namespace}",
                "risk": "low",
                "confidence": 0.95,
                "description": "Log level'ı düşür ve hassas verilerin loglanmasını durdur"
            },
            {
                "action": "Tüm etkilenen secret'ları rotate et",
                "command": "kubectl create secret generic {service}-credentials --from-literal=DB_PASSWORD=$(openssl rand -base64 32) -n {namespace} --dry-run=client -o yaml | kubectl apply -f -",
                "risk": "medium",
                "confidence": 0.90,
                "description": "Expose olmuş tüm credential'ları yenile"
            }
        ]
    },
    "configmap_missing": {
        "symptoms": ["ConfigMap not found", "configmap", "mount failed", "missing configuration"],
        "diagnosis_steps": [
            "Pod events'lerini kontrol et",
            "Namespace'teki ConfigMap'leri listele",
            "Pod spec'indeki volume referanslarını doğrula",
            "Diğer namespace'lerde ConfigMap'in varlığını kontrol et"
        ],
        "remediation_options": [
            {
                "action": "Eksik ConfigMap'i oluştur",
                "command": "kubectl get configmap {service}-config -n old-namespace -o yaml | sed 's/namespace: old-namespace/namespace: {namespace}/' | kubectl apply -f -",
                "risk": "low",
                "confidence": 0.90,
                "description": "ConfigMap'i doğru namespace'e kopyala"
            },
            {
                "action": "ConfigMap'i sıfırdan oluştur",
                "command": "kubectl create configmap {service}-config --from-file=config/ -n {namespace}",
                "risk": "medium",
                "confidence": 0.75,
                "description": "Yeni ConfigMap oluştur"
            }
        ]
    },
    "quota_exceeded": {
        "symptoms": ["quota", "exceeded", "forbidden", "resource limit", "cannot create pod"],
        "diagnosis_steps": [
            "ResourceQuota kullanımını kontrol et",
            "Completed/Failed pod'ları listele",
            "Her deployment'ın resource request'lerini incele",
            "Gereksiz kaynak tüketen workload'ları belirle"
        ],
        "remediation_options": [
            {
                "action": "Zombie pod'ları temizle",
                "command": "kubectl delete pods --field-selector=status.phase=Succeeded -n {namespace} && kubectl delete pods --field-selector=status.phase=Failed -n {namespace}",
                "risk": "low",
                "confidence": 0.90,
                "description": "Tamamlanmış ama silinmemiş pod'ları kaldır"
            },
            {
                "action": "Namespace quota'sını artır",
                "command": "kubectl patch resourcequota production-quota -n {namespace} -p '{{\"spec\":{{\"hard\":{{\"cpu\":\"48\",\"memory\":\"96Gi\"}}}}}}'",
                "risk": "medium",
                "confidence": 0.80,
                "description": "Kaynak limitlerini artır"
            }
        ]
    },
    "node_failure": {
        "symptoms": ["NotReady", "NodeCondition", "kubelet", "heartbeat", "unreachable"],
        "diagnosis_steps": [
            "Node conditions'ları kontrol et (kubectl describe node)",
            "Cloud provider VM durumunu doğrula",
            "Diğer node'larda yeterli kapasite olup olmadığını kontrol et",
            "Evicted pod'ların yeniden schedule durumunu izle"
        ],
        "remediation_options": [
            {
                "action": "Node'u drain et ve pod'ları taşı",
                "command": "kubectl drain {node} --ignore-daemonsets --force --delete-emptydir-data",
                "risk": "medium",
                "confidence": 0.90,
                "description": "Pod'ları sağlıklı node'lara yeniden schedule et"
            },
            {
                "action": "Yeni node ekle (cluster auto-scaler)",
                "command": "kubectl scale nodepool default-pool --num-nodes=5",
                "risk": "low",
                "confidence": 0.80,
                "description": "Cluster kapasitesini artır"
            }
        ]
    },
    "hpa_instability": {
        "symptoms": ["HPA", "thrashing", "scale", "oscillation", "fluctuating", "autoscal"],
        "diagnosis_steps": [
            "HPA events ve scaling geçmişini kontrol et",
            "CPU/memory metrik grafiklerini incele",
            "stabilizationWindowSeconds ayarını kontrol et",
            "Pod warm-up süresini değerlendir"
        ],
        "remediation_options": [
            {
                "action": "Stabilization window ekle",
                "command": "kubectl patch hpa {service} -n {namespace} -p '{{\"spec\":{{\"behavior\":{{\"scaleDown\":{{\"stabilizationWindowSeconds\":300,\"policies\":[{{\"type\":\"Percent\",\"value\":10,\"periodSeconds\":60}}]}}}}}}}}'",
                "risk": "low",
                "confidence": 0.90,
                "description": "Scale-down kararlarını yavaşlat"
            },
            {
                "action": "CPU target'ı ayarla",
                "command": "kubectl patch hpa {service} -n {namespace} -p '{{\"spec\":{{\"metrics\":[{{\"type\":\"Resource\",\"resource\":{{\"name\":\"cpu\",\"target\":{{\"type\":\"Utilization\",\"averageUtilization\":80}}}}}}]}}}}'",
                "risk": "low",
                "confidence": 0.80,
                "description": "CPU threshold'unu artırarak gereksiz scale'i azalt"
            }
        ]
    },
    "etcd_degradation": {
        "symptoms": ["etcd", "slow apply", "fsync", "leader change", "compaction", "db size"],
        "diagnosis_steps": [
            "ETCD metriklerini kontrol et (etcdctl endpoint status)",
            "Disk I/O performansını ölç",
            "DB boyutunu ve compaction geçmişini kontrol et",
            "Leader election sıklığını incele"
        ],
        "remediation_options": [
            {
                "action": "ETCD defragmentation ve compaction çalıştır",
                "command": "etcdctl defrag --cluster && etcdctl compact $(etcdctl endpoint status -w json | jq '.[0].Status.header.revision')",
                "risk": "medium",
                "confidence": 0.85,
                "description": "DB boyutunu küçült ve performansı iyileştir"
            },
            {
                "action": "ETCD disk'ini SSD'ye taşı",
                "command": "Disk migration plan oluştur ve uygula",
                "risk": "high",
                "confidence": 0.90,
                "description": "Kalıcı çözüm: hızlı storage'a geçiş"
            }
        ]
    },
    "rollout_stuck": {
        "symptoms": ["rollout", "stuck", "ProgressDeadlineExceeded", "rolling update", "deployment stuck"],
        "diagnosis_steps": [
            "Rollout status kontrol et (kubectl rollout status)",
            "Yeni pod'ların events'lerini incele",
            "Init container veya startup loglarını kontrol et",
            "Resource availability'yi doğrula"
        ],
        "remediation_options": [
            {
                "action": "Rollback yap",
                "command": "kubectl rollout undo deployment/{service} -n {namespace}",
                "risk": "low",
                "confidence": 0.90,
                "description": "Son çalışan versiyona geri dön"
            },
            {
                "action": "Migration'ı ayrı job olarak çalıştır",
                "command": "kubectl create job --from=cronjob/{service}-migration {service}-migration-manual -n {namespace}",
                "risk": "medium",
                "confidence": 0.80,
                "description": "DB migration'ı deployment'tan ayır"
            }
        ]
    }
}

# ─── Senaryo ↔ Runbook Eşleştirmesi ───
SCENARIO_RUNBOOK_MAP = {
    "oom_kill_memory_leak": "oom_kill",
    "crash_loop_backoff": "crash_loop",
    "image_pull_backoff": "image_pull",
    "liveness_probe_failure": "probe_failure",
    "cascading_latency": "high_latency",
    "dns_resolution_failure": "dns_failure",
    "ingress_backend_502": "ingress_error",
    "node_pressure": "disk_pressure",
    "pvc_mount_failure": "pvc_failure",
    "persistent_volume_full": "volume_full",
    "security_breach_attempt": "security_incident",
    "rbac_permission_denied": "rbac_issue",
    "secret_leak_detection": "secret_leak",
    "config_drift_ssl": "ssl_cert",
    "configmap_not_found": "configmap_missing",
    "resource_quota_exceeded": "quota_exceeded",
    "node_not_ready": "node_failure",
    "hpa_thrashing": "hpa_instability",
    "etcd_latency_degradation": "etcd_degradation",
    "failed_rolling_update": "rollout_stuck"
}


@dataclass
class ReActStep:
    """Bir ReAct reasoning adımı."""
    step_number: int
    thought: str
    action: Optional[str] = None
    action_input: Optional[str] = None
    observation: Optional[str] = None
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return asdict(self)


@dataclass
class RemediationPlan:
    """Yapılandırılmış remediation planı."""
    id: str
    alert_id: str
    scenario_id: str
    severity: str
    root_cause_analysis: str
    confidence_score: float
    selected_action: dict
    alternative_actions: list
    rollback_plan: str
    validation_steps: list
    react_trace: list  # ReAct step'leri
    confidence_factors: dict = field(default_factory=dict)
    status: str = "pending"  # pending, approved, executing, completed, failed
    execution_result: Optional[dict] = None
    created_at: str = ""
    completed_at: Optional[str] = None

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()

    def to_dict(self):
        d = asdict(self)
        return d


class ConfidenceCalculator:
    """
    Çok faktörlü güven skoru hesaplama motoru.
    5 bağımsız faktörü ağırlıklı ortalama ile birleştirerek
    0.0–1.0 arası anlamlı bir skor üretir.
    """

    WEIGHTS = {
        "symptom_match": 0.25,
        "metric_anomaly": 0.20,
        "runbook_coverage": 0.20,
        "evidence_richness": 0.15,
        "action_specificity": 0.20,
    }

    @staticmethod
    def calculate(alert: dict, runbook: dict, runbook_key: str,
                  selected_action: dict = None, scenario_id: str = None) -> dict:
        factors = {}

        factors["symptom_match"] = ConfidenceCalculator._symptom_match_score(
            alert, runbook)
        factors["metric_anomaly"] = ConfidenceCalculator._metric_anomaly_score(
            alert)
        factors["runbook_coverage"] = ConfidenceCalculator._runbook_coverage_score(
            runbook)
        factors["evidence_richness"] = ConfidenceCalculator._evidence_richness_score(
            alert)
        factors["action_specificity"] = ConfidenceCalculator._action_specificity_score(
            selected_action)

        weighted_sum = sum(
            score * ConfidenceCalculator.WEIGHTS[name]
            for name, score in factors.items()
        )
        overall = round(min(0.99, max(0.05, weighted_sum)), 2)

        return {
            "overall": overall,
            "factors": {k: round(v, 2) for k, v in factors.items()},
            "weights": ConfidenceCalculator.WEIGHTS,
        }

    @staticmethod
    def _symptom_match_score(alert: dict, runbook: dict) -> float:
        """Runbook semptomlarının alert açıklaması ile ne kadar eşleştiği."""
        symptoms = runbook.get("symptoms", [])
        if not symptoms:
            return 0.0
        desc = (alert.get("description", "") + " " +
                alert.get("title", "")).lower()
        matched = sum(1 for s in symptoms if s.lower() in desc)
        return min(1.0, matched / max(1, len(symptoms)) * 1.5)

    @staticmethod
    def _metric_anomaly_score(alert: dict) -> float:
        """Metriklerdeki anomali şiddeti — anormal metrik oranı."""
        metrics = alert.get("metrics", {})
        if not metrics:
            return 0.0

        anomaly_count = 0
        total = 0
        for key, val in metrics.items():
            if not isinstance(val, (int, float)):
                if isinstance(val, bool) and val:
                    anomaly_count += 1
                total += 1
                continue
            total += 1
            k = key.lower()
            if "error" in k or "failure" in k or "breach" in k:
                if val > 5:
                    anomaly_count += 1
            elif "latency" in k or "ms" in k:
                if val > 1000:
                    anomaly_count += 1
                elif val > 500:
                    anomaly_count += 0.5
            elif "usage" in k or "percent" in k:
                if val > 90:
                    anomaly_count += 1
                elif val > 75:
                    anomaly_count += 0.5
            elif "restart" in k:
                if val > 10:
                    anomaly_count += 1
                elif val > 3:
                    anomaly_count += 0.5
            elif val > 100:
                anomaly_count += 0.3

        ratio = anomaly_count / max(1, total)
        return min(1.0, ratio * 1.4)

    @staticmethod
    def _runbook_coverage_score(runbook: dict) -> float:
        """Runbook'un ne kadar kapsamlı olduğu."""
        if not runbook:
            return 0.0
        score = 0.0
        diag_steps = runbook.get("diagnosis_steps", [])
        rem_options = runbook.get("remediation_options", [])
        symptoms = runbook.get("symptoms", [])

        if symptoms:
            score += min(0.3, len(symptoms) * 0.075)
        if diag_steps:
            score += min(0.35, len(diag_steps) * 0.09)
        if rem_options:
            score += min(0.35, len(rem_options) * 0.12)
            has_low_risk = any(o.get("risk") == "low" for o in rem_options)
            if has_low_risk:
                score += 0.05
        return min(1.0, score)

    @staticmethod
    def _evidence_richness_score(alert: dict) -> float:
        """Alert'teki kanıt zenginliği — metrik/pod/servis bilgisi."""
        score = 0.0
        metrics = alert.get("metrics", {})
        pod_info = alert.get("pod_info", {})
        desc = alert.get("description", "")

        metric_count = len(metrics)
        if metric_count >= 6:
            score += 0.35
        elif metric_count >= 3:
            score += 0.2
        elif metric_count >= 1:
            score += 0.1

        if pod_info:
            pod_fields = sum(1 for v in pod_info.values() if v)
            score += min(0.3, pod_fields * 0.06)

        desc_len = len(desc)
        if desc_len > 200:
            score += 0.2
        elif desc_len > 100:
            score += 0.15
        elif desc_len > 30:
            score += 0.08

        if alert.get("related_services"):
            score += 0.15

        return min(1.0, score)

    @staticmethod
    def _action_specificity_score(action: dict) -> float:
        """Seçilen aksiyonun ne kadar spesifik ve uygulanabilir olduğu."""
        if not action:
            return 0.0
        score = 0.0
        cmd = action.get("command", "")
        if cmd and cmd != "N/A":
            score += 0.3
            if "kubectl" in cmd:
                score += 0.2
            if "-n " in cmd:
                score += 0.1
            if len(cmd) > 50:
                score += 0.1
        if action.get("description"):
            score += 0.15
        if action.get("risk") in ("low", "medium", "high"):
            score += 0.15

        return min(1.0, score)


class LLMRemediationAgent:
    """
    LLM tabanlı remediation agent'ı.
    ReAct pattern kullanarak anomalileri analiz eder ve çözüm üretir.
    Simülasyon modunda gerçek LLM olmadan da çalışır.
    """

    def __init__(self, mode="simulation"):
        """
        mode: "simulation" veya "llm"
        simulation: Yerleşik bilgi tabanı ve deterministik mantıkla çalışır
        llm: Gerçek LLM API'si kullanır (OpenAI vs.)
        """
        self.mode = mode
        self.knowledge_base = RUNBOOK_KNOWLEDGE
        self.scenario_map = SCENARIO_RUNBOOK_MAP
        self.history = []  # Geçmiş remediation'lar

    def analyze_and_remediate(self, alert_data: dict, scenario_id: str = None,
                              kubectl_logs: str = None, kubectl_pods: str = None,
                              rule_context: dict = None) -> RemediationPlan:
        """
        Alert verisini analiz eder ve remediation planı üretir.
        Moda göre gerçek LLM API'sine veya simülasyona yönlendirir.
        """
        if self.mode == "llm":
            return self._analyze_with_llm(alert_data, scenario_id, kubectl_logs, kubectl_pods, rule_context)
            
        # Simülasyon modu (Rule-Based)
        react_steps = []
        step_num = 0

        # ─── STEP 1: İlk Analiz (THOUGHT) ───
        step_num += 1
        thought1 = self._generate_initial_thought(alert_data)
        react_steps.append(ReActStep(
            step_number=step_num,
            thought=thought1,
            action="analyze_alert",
            action_input=json.dumps({"alert_id": alert_data.get("id", "unknown"), "severity": alert_data.get("severity")}),
            observation=f"Alert alındı: {alert_data.get('title', 'Unknown')} | Severity: {alert_data.get('severity', 'unknown')}"
        ))

        # ─── STEP 2: Symptom Matching (ACTION: knowledge base query) ───
        step_num += 1
        runbook_key = self._match_runbook(alert_data, scenario_id)
        runbook = self.knowledge_base.get(runbook_key, {}) if runbook_key else {}
        is_unknown = not runbook_key or not runbook

        if is_unknown:
            react_steps.append(ReActStep(
                step_number=step_num,
                thought=f"Semptomları bilgi tabanındaki runbook'larla eşleştiriyorum. "
                        f"Alert açıklamasındaki anahtar kelimeler: {self._extract_keywords(alert_data)}",
                action="query_knowledge_base",
                action_input=f"runbook_key: None",
                observation="⚠️ BİLGİ TABANINDA EŞLEŞMİYOR — Bu incident için tanımlanmış bir runbook bulunamadı. "
                            "Rule-based sistem bu tür bilinmeyen anomalileri çözme kapasitesine sahip değil."
            ))
            return self._generate_unknown_incident_plan(alert_data, scenario_id, react_steps, step_num)

        react_steps.append(ReActStep(
            step_number=step_num,
            thought=f"Semptomları bilgi tabanındaki runbook'larla eşleştiriyorum. "
                    f"Alert açıklamasındaki anahtar kelimeler: {self._extract_keywords(alert_data)}",
            action="query_knowledge_base",
            action_input=f"runbook_key: {runbook_key}",
            observation=f"Eşleşen runbook bulundu: '{runbook_key}' | "
                        f"Tanı adımları: {len(runbook.get('diagnosis_steps', []))} | "
                        f"Çözüm seçenekleri: {len(runbook.get('remediation_options', []))}"
        ))

        # ─── STEP 3: Pod/Service Investigation (ACTION: kubectl simulation) ───
        step_num += 1
        pod_info = alert_data.get("pod_info", {})
        metrics = alert_data.get("metrics", {})

        diagnosis_details = self._run_diagnosis(runbook, alert_data)
        react_steps.append(ReActStep(
            step_number=step_num,
            thought=f"Pod ve servis durumlarını inceliyorum. "
                    f"Pod: {pod_info.get('name', 'N/A')} | Status: {pod_info.get('status', 'N/A')} | "
                    f"Restarts: {pod_info.get('restarts', 0)}",
            action="investigate_infrastructure",
            action_input=f"kubectl describe pod {pod_info.get('name', 'unknown')}",
            observation=diagnosis_details
        ))

        # ─── STEP 4: Root Cause Determination (THOUGHT: reasoning) ───
        step_num += 1
        rca = self._determine_root_cause(alert_data, runbook, scenario_id)
        react_steps.append(ReActStep(
            step_number=step_num,
            thought=f"Kök neden analizi yapıyorum. Toplanan kanıtlara dayanarak: {rca['summary']}",
            action="root_cause_analysis",
            action_input=json.dumps({"evidence_count": rca["evidence_count"]}),
            observation=f"Kök Neden: {rca['root_cause']}"
        ))

        # ─── STEP 5: Remediation Selection (THOUGHT + ACTION) ───
        step_num += 1
        remediation_options = runbook.get("remediation_options", [])
        selected, alternatives = self._select_remediation(remediation_options, alert_data)

        service_name = alert_data.get("source_service", "unknown")
        namespace = alert_data.get("namespace", "default")

        replacements = {
            "{service}": service_name,
            "{namespace}": namespace,
            "{target_replicas}": "15",
            "{culprit}": "analytics-daily",
            "{node}": "worker-node-03",
            "{cert_name}": "api-tls"
        }
        if selected:
            for old, new in replacements.items():
                selected["command"] = selected["command"].replace(old, new)
            for alt in alternatives:
                for old, new in replacements.items():
                    alt["command"] = alt["command"].replace(old, new)

        react_steps.append(ReActStep(
            step_number=step_num,
            thought=f"En uygun remediation eylemini seçiyorum. "
                    f"{len(remediation_options)} seçenek değerlendirildi. "
                    f"Risk-fayda analizi yapıldı. "
                    f"Seçilen: '{selected.get('action', 'N/A')}'",
            action="select_remediation",
            action_input=json.dumps(selected) if selected else "{}",
            observation=f"Seçilen eylem: {selected.get('action', 'N/A')} | "
                        f"Komut: {selected.get('command', 'N/A')} | "
                        f"Risk: {selected.get('risk', 'N/A')}"
        ))

        # ─── STEP 6: Güven Skoru Hesaplama ───
        step_num += 1
        conf_result = ConfidenceCalculator.calculate(
            alert_data, runbook, runbook_key, selected, scenario_id)
        factors = conf_result["factors"]
        overall = conf_result["overall"]

        factor_lines = " | ".join(
            f"{k}: %{v*100:.0f}" for k, v in factors.items())
        react_steps.append(ReActStep(
            step_number=step_num,
            thought=f"Çok faktörlü güven skoru hesaplanıyor. "
                    f"5 bağımsız faktör ağırlıklı ortalaması ile skor üretiliyor.",
            action="calculate_confidence",
            action_input=json.dumps(conf_result["factors"]),
            observation=f"GÜVEN SKORU: %{overall*100:.0f}\n"
                        f"  Semptom Eşleşme: %{factors['symptom_match']*100:.0f} (ağırlık: %25)\n"
                        f"  Metrik Anomali: %{factors['metric_anomaly']*100:.0f} (ağırlık: %20)\n"
                        f"  Runbook Kapsamı: %{factors['runbook_coverage']*100:.0f} (ağırlık: %20)\n"
                        f"  Kanıt Zenginliği: %{factors['evidence_richness']*100:.0f} (ağırlık: %15)\n"
                        f"  Aksiyon Spesifikliği: %{factors['action_specificity']*100:.0f} (ağırlık: %20)"
        ))

        # ─── STEP 7: Validation Plan (THOUGHT) ───
        step_num += 1
        validation_steps = self._create_validation_plan(alert_data, selected)
        react_steps.append(ReActStep(
            step_number=step_num,
            thought=f"Doğrulama planı oluşturuyorum. Remediation sonrası {len(validation_steps)} kontrol adımı uygulanacak.",
            action="create_validation_plan",
            action_input=json.dumps({"steps_count": len(validation_steps)}),
            observation=f"Doğrulama planı hazır: {', '.join(validation_steps[:3])}..."
        ))

        # ─── Remediation Planı Oluştur ───
        plan = RemediationPlan(
            id=f"REM-{uuid.uuid4().hex[:8].upper()}",
            alert_id=alert_data.get("id", "unknown"),
            scenario_id=scenario_id or "unknown",
            severity=alert_data.get("severity", "unknown"),
            root_cause_analysis=rca["root_cause"],
            confidence_score=overall,
            selected_action=selected,
            alternative_actions=alternatives,
            rollback_plan=self._generate_rollback_plan(selected, service_name, namespace),
            validation_steps=validation_steps,
            react_trace=[step.to_dict() for step in react_steps],
            confidence_factors=conf_result["factors"],
            status="pending"
        )

        self.history.append(plan.to_dict())
        return plan

    def _generate_unknown_incident_plan(self, alert_data, scenario_id, react_steps, step_num):
        """Runbook'ta olmayan bilinmeyen incident'lar için sınırlı bir plan üretir."""
        step_num += 1
        react_steps.append(ReActStep(
            step_number=step_num,
            thought="Bilgi tabanında bu anomali pattern'i için eşleşme bulunamadı. "
                    "Rule-based sistem yalnızca önceden tanımlanmış runbook'lardaki senaryoları çözebilir. "
                    "Bu bilinmeyen durum için yeterli veri ve kural seti mevcut değil.",
            action="fallback_analysis",
            action_input="generic_troubleshooting",
            observation="❌ Spesifik tanı ve çözüm üretilemiyor. "
                        "Genel troubleshooting önerileri sunulabilir ancak kök neden tespiti yapılamaz."
        ))

        step_num += 1
        react_steps.append(ReActStep(
            step_number=step_num,
            thought="Bu tip bilinmeyen anomaliler için LLM-based analiz önerilir. "
                    "LLM, eğitim verisindeki geniş bilgi sayesinde daha önce karşılaşılmamış "
                    "pattern'leri de analiz edebilir.",
            action="recommendation",
            action_input="switch_to_llm_mode",
            observation="ÖNERİ: Bu incident için LLM-Based modu kullanın. "
                        "Rule-Based sistem tanımlanmamış senaryolarda yetersiz kalır."
        ))

        unknown_action = {
            "action": "Genel Pod Restart (düşük güvenli genel çözüm)",
            "command": f"kubectl rollout restart deployment/{alert_data.get('source_service', 'unknown')} -n {alert_data.get('namespace', 'default')}",
            "risk": "medium",
            "confidence": 0.15,
            "description": "Kök neden belirlenemediği için sadece genel restart önerilebilir"
        }
        unknown_conf = ConfidenceCalculator.calculate(
            alert_data, {}, None, unknown_action, scenario_id)

        return RemediationPlan(
            id=f"REM-{uuid.uuid4().hex[:8].upper()}",
            alert_id=alert_data.get("id", "unknown"),
            scenario_id=scenario_id or "unknown",
            severity=alert_data.get("severity", "unknown"),
            root_cause_analysis="TANIMLANAMIYOR — Bu anomali pattern'i bilgi tabanindaki hicbir runbook ile eslesiyor. "
                                "Rule-based sistem yalnizca onceden tanimlanmis senaryolari cozebilir. "
                                "Bilinmeyen incident'lar icin LLM-Based moda gecmeniz onerilir.",
            confidence_score=unknown_conf["overall"],
            confidence_factors=unknown_conf["factors"],
            selected_action=unknown_action,
            alternative_actions=[{
                "action": "LLM-Based moda geç (önerilen)",
                "command": "Mod seçiciyi LLM-Based olarak değiştirin",
                "risk": "low",
                "confidence": 0.95,
                "description": "LLM, bilinmeyen pattern'leri analiz edebilir"
            }],
            rollback_plan="Genel restart uygulandıysa: önceki replica count'u doğrula, "
                          "servis sağlığını kontrol et",
            validation_steps=[
                "Pod durumlarını kontrol et",
                "Servis yanıt sürelerini doğrula"
            ],
            react_trace=[s.to_dict() for s in react_steps],
            status="pending"
        )

    def execute_plan(self, plan: RemediationPlan) -> dict:
        """Remediation planını 'çalıştırır' (simülasyon)."""
        plan.status = "executing"
        time.sleep(0.5)  # Simülasyon gecikmesi

        result = {
            "success": True,
            "plan_id": plan.id,
            "action_executed": plan.selected_action.get("action", "N/A"),
            "command_executed": plan.selected_action.get("command", "N/A"),
            "execution_time_ms": round(time.time() * 1000) % 5000 + 500,
            "validation_results": [
                {"step": step, "passed": True} for step in plan.validation_steps
            ],
            "status": "completed",
            "completed_at": datetime.now().isoformat()
        }
        plan.status = "completed"
        plan.completed_at = datetime.now().isoformat()
        plan.execution_result = result
        return result

    # ─── Gerçek LLM (Model-Based) Entegrasyonu ───

    def _analyze_with_llm(self, alert_data: dict, scenario_id: str,
                          kubectl_logs: str = None, kubectl_pods: str = None,
                          rule_context: dict = None) -> RemediationPlan:
        import requests as http_requests
        import os

        provider = os.environ.get("LLM_PROVIDER", "groq").lower()

        if provider == "groq":
            api_key = os.environ.get("GROQ_API_KEY")
            model = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
            api_url = "https://api.groq.com/openai/v1/chat/completions"
        else:
            api_key = os.environ.get("OPENAI_API_KEY")
            model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
            api_url = "https://api.openai.com/v1/chat/completions"

        if not api_key:
            raise ValueError(f"{provider.upper()} API key ayarlanmamış.")

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        system_prompt = """Sen kıdemli bir Site Reliability Engineer (SRE) ve Kubernetes uzmanısın. 
Görevin, production Kubernetes cluster'larındaki anomalileri ReAct (Reasoning + Acting) metodolojisi ile analiz edip çözmek.

ReAct Metodolojisi:
- Her adımda önce DÜŞÜN (thought), sonra bir EYLEM (action) gerçekleştir, ardından sonucu GÖZLEMLE (observation).
- Minimum 5, maksimum 7 ReAct adımı üret.
- Her adım birbirinden farklı bir analiz boyutunu kapsamalı.

Adım Tipleri (sırayla):
1. alert_triage — Alert'i sınıflandır, severity'yi değerlendir, ilk hipotezi oluştur
2. analyze_metrics — Metriklerdeki anomali pattern'lerini tespit et
3. investigate_logs — kubectl loglarından root cause ipuçları çıkar
4. investigate_infrastructure — Pod/node/service durumlarını incele  
5. root_cause_analysis — Tüm kanıtları birleştirerek kök nedeni belirle
6. select_remediation — Risk-fayda analizi yaparak en uygun çözümü seç
7. create_validation_plan — Düzeltme sonrası doğrulama planı oluştur

ZORUNLU ÇIKTI FORMATI (sadece JSON, markdown yok):
{
    "root_cause_analysis": "Detaylı teknik kök neden açıklaması (en az 2-3 cümle)",
    "confidence_score": 0.85,
    "selected_action": {
        "action": "Ana aksiyonun kısa adı",
        "command": "Tam kubectl komutu — tüm parametreler doldurulmuş, kopyala-yapıştır hazır",
        "risk": "low|medium|high",
        "confidence": 0.90,
        "description": "Bu aksiyonun sorunu nasıl çözeceğinin açıklaması"
    },
    "alternative_actions": [
        {
            "action": "Alternatif aksiyon adı",
            "command": "Alternatif kubectl komutu",
            "risk": "low|medium|high",
            "confidence": 0.70,
            "description": "Açıklama"
        }
    ],
    "validation_steps": [
        "kubectl get pods ile pod durumlarını doğrula",
        "Error rate metriklerini izle",
        "Downstream servislerin sağlığını kontrol et",
        "5 dakika boyunca yeni alert oluşmadığını onayla"
    ],
    "react_trace": [
        {
            "step_number": 1,
            "thought": "Detaylı düşünce — ne gördüm, ne anlıyorum, hipotezim ne",
            "action": "alert_triage",
            "action_input": "Çalıştırılan komut veya sorgu",
            "observation": "Elde edilen somut sonuç"
        }
    ]
}"""

        if rule_context:
            system_prompt += """

RULE-BASED HANDOFF MODE:
- Rule-based agent zaten kisa aralikli control-loop icinde ilk ReAct analizini yapti.
- Sen sifirdan kopuk bir analiz yapma; once rule-based ReAct trace'ini ve gecici plani dogrula.
- Eksik veya hatali nokta varsa duzelt, daha guvenli bir plan varsa kontrolu devral.
- Ilk ReAct adiminin action alani "rule_handoff_review" olsun.
"""

        log_section = ""
        if kubectl_logs:
            log_section = f"""
--- kubectl logs (son çıktı) ---
{kubectl_logs}
"""
        pod_section = ""
        rule_context_section = ""
        if kubectl_pods:
            pod_section = f"""
--- kubectl get pods ---
{kubectl_pods}
"""
        if rule_context:
            rule_context_section = f"""
--- RULE-BASED HANDOFF CONTEXT ---
Rule-based agent 100ms control-loop icinde asagidaki gecici plani uretti.
LLM gorevi: Bu ReAct trace'i ve gecici plani devral, dogrula, gerekirse duzelt veya daha iyi bir planla kontrolu al.
{json.dumps(rule_context, indent=2, ensure_ascii=False)}
"""

        user_prompt = f"""Aşağıdaki Kubernetes cluster alert'ini ReAct metodolojisi ile analiz et ve çözüm üret.

═══ ALERT BİLGİLERİ ═══
Başlık: {alert_data.get('title', 'N/A')}
Severity: {alert_data.get('severity', 'N/A')}
Service: {alert_data.get('source_service', 'N/A')}
Namespace: {alert_data.get('namespace', 'N/A')}
Açıklama: {alert_data.get('description', 'N/A')}

═══ METRİKLER ═══
{json.dumps(alert_data.get('metrics', {}), indent=2, ensure_ascii=False)}

═══ POD BİLGİSİ ═══
{json.dumps(alert_data.get('pod_info', {}), indent=2, ensure_ascii=False)}

═══ İLİŞKİLİ SERVİSLER ═══
{', '.join(alert_data.get('related_services', []))}
{log_section}{pod_section}{rule_context_section}
Yukarıdaki tüm verileri kullanarak derinlemesine bir ReAct analizi yap. Minimum 5 adım üret. Yanıtını SADECE JSON formatında ver."""

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 3000
        }

        response = http_requests.post(
            api_url,
            headers=headers, json=payload, timeout=45
        )
        response.raise_for_status()

        content = response.json()["choices"][0]["message"]["content"].strip()

        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()

        llm_result = json.loads(content)

        react_steps = []
        for trace in llm_result.get("react_trace", []):
            react_steps.append(ReActStep(
                step_number=trace.get("step_number", 0),
                thought=trace.get("thought", ""),
                action=trace.get("action", ""),
                action_input=trace.get("action_input", ""),
                observation=trace.get("observation", "")
            ))

        service_name = alert_data.get("source_service", "unknown")
        namespace = alert_data.get("namespace", "default")

        selected = llm_result.get("selected_action", {})
        if "description" not in selected:
            selected["description"] = selected.get("action", "")

        runbook_key = self._match_runbook(alert_data, scenario_id)
        runbook = self.knowledge_base.get(runbook_key, {}) if runbook_key else {}
        calc_result = ConfidenceCalculator.calculate(
            alert_data, runbook, runbook_key, selected, scenario_id)

        llm_score = llm_result.get("confidence_score", 0.5)
        calc_score = calc_result["overall"]
        blended = round(llm_score * 0.40 + calc_score * 0.60, 2)

        conf_factors = calc_result["factors"]
        conf_factors["llm_self_assessment"] = round(llm_score, 2)
        conf_factors["_blending"] = f"LLM(%40)={llm_score:.2f} + Hesaplanan(%60)={calc_score:.2f} = {blended:.2f}"

        plan = RemediationPlan(
            id=f"REM-LLM-{uuid.uuid4().hex[:6].upper()}",
            alert_id=alert_data.get("id", "unknown"),
            scenario_id=scenario_id or "unknown",
            severity=alert_data.get("severity", "unknown"),
            root_cause_analysis=llm_result.get("root_cause_analysis", "Bilinmeyen kök neden"),
            confidence_score=blended,
            selected_action=selected,
            alternative_actions=llm_result.get("alternative_actions", []),
            rollback_plan=self._generate_rollback_plan(selected, service_name, namespace),
            validation_steps=llm_result.get("validation_steps", []),
            react_trace=[step.to_dict() for step in react_steps],
            confidence_factors=conf_factors,
            status="pending"
        )

        self.history.append(plan.to_dict())
        return plan

    # ─── Private Helper Methods ───

    def _generate_initial_thought(self, alert: dict) -> str:
        severity = alert.get("severity", "unknown")
        title = alert.get("title", "Unknown Alert")
        sev_map = {
            "critical": "Bu KRITIK seviye bir alert. Hemen müdahale gerekiyor.",
            "high": "Bu YÜKSEK seviye bir alert. Hızlı analiz ve müdahale gerekli.",
            "medium": "Bu ORTA seviye bir alert. Sistematik analiz yapılmalı.",
            "low": "Bu DÜŞÜK seviye bir alert. İzleme ve proaktif müdahale değerlendirilmeli."
        }
        return (
            f"Yeni alert alındı: '{title}'. "
            f"{sev_map.get(severity, 'Bilinmeyen seviye.')} "
            f"Önce durumu anlamak için sistemi sorgulayacağım."
        )

    def _extract_keywords(self, alert: dict) -> list:
        desc = alert.get("description", "").lower()
        keywords = []
        keyword_map = {
            "oom": "OOM/Memory", "memory": "OOM/Memory", "heap": "OOM/Memory",
            "crashloop": "CrashLoop", "crash loop": "CrashLoop", "crash_loop": "CrashLoop",
            "imagepull": "Image Pull", "image pull": "Image Pull", "registry": "Image Pull",
            "liveness": "Health Probe", "readiness": "Health Probe", "probe": "Health Probe",
            "latency": "Latency", "timeout": "Timeout", "connection pool": "Connection Pool",
            "dns": "DNS", "coredns": "DNS", "resolve": "DNS",
            "502": "Ingress/Gateway", "bad gateway": "Ingress/Gateway", "ingress": "Ingress/Gateway",
            "ssl": "SSL/TLS", "certificate": "SSL/TLS", "cert": "SSL/TLS",
            "disk": "Disk I/O", "i/o": "Disk I/O", "pressure": "Resource Pressure",
            "pvc": "Storage/PVC", "persistent volume": "Storage/PVC", "mount": "Storage/PVC",
            "wal": "Database", "read-only": "Database", "write blocked": "Database",
            "security": "Security", "suspicious": "Security", "cve": "Security",
            "crypto": "Security", "brute force": "Security",
            "rbac": "RBAC", "permission denied": "RBAC", "forbidden": "RBAC",
            "secret": "Secret Leak", "credential": "Secret Leak", "leak": "Secret Leak",
            "configmap": "ConfigMap", "config map": "ConfigMap",
            "quota": "Resource Quota", "exceeded": "Resource Quota",
            "notready": "Node Health", "not ready": "Node Health", "kubelet": "Node Health",
            "hpa": "HPA/Autoscaling", "thrash": "HPA/Autoscaling", "oscillat": "HPA/Autoscaling",
            "etcd": "ETCD", "fsync": "ETCD",
            "rollout": "Rollout", "rolling update": "Rollout", "stuck": "Rollout"
        }
        for key, label in keyword_map.items():
            if key in desc and label not in keywords:
                keywords.append(label)
        return keywords or ["General"]

    def _match_runbook(self, alert: dict, scenario_id: str = None) -> str:
        if scenario_id and scenario_id in self.scenario_map:
            return self.scenario_map[scenario_id]
        if scenario_id and scenario_id not in self.scenario_map:
            return None
        desc = alert.get("description", "").lower()
        for rk, rb in self.knowledge_base.items():
            for symptom in rb["symptoms"]:
                if symptom.lower() in desc:
                    return rk
        return None

    def _run_diagnosis(self, runbook: dict, alert: dict) -> str:
        steps = runbook.get("diagnosis_steps", [])
        metrics = alert.get("metrics", {})
        lines = ["Tanı Adımları Uygulandı:"]
        for i, step in enumerate(steps, 1):
            lines.append(f"  [{i}] ✅ {step}")
        lines.append(f"\nMetrik Özeti:")
        for k, v in list(metrics.items())[:5]:
            lines.append(f"  • {k}: {v}")
        return "\n".join(lines)

    def _determine_root_cause(self, alert: dict, runbook: dict, scenario_id: str) -> dict:
        from simulator.cloud_simulator import INCIDENT_SCENARIOS
        scenario = next((s for s in INCIDENT_SCENARIOS if s["id"] == scenario_id), None) if scenario_id else None
        if scenario:
            return {
                "root_cause": scenario["root_cause"],
                "confidence": 0.87,
                "evidence_count": len(alert.get("metrics", {})),
                "summary": f"Kanıtlara dayalı analiz tamamlandı. {len(alert.get('metrics', {}))} metrik incelendi."
            }
        return {
            "root_cause": "Belirlenemedi — daha fazla veri gerekiyor",
            "confidence": 0.40,
            "evidence_count": 0,
            "summary": "Yetersiz veri"
        }

    def _select_remediation(self, options: list, alert: dict) -> tuple:
        if not options:
            return {"action": "Manual intervention required", "command": "N/A", "risk": "N/A", "confidence": 0}, []
        severity = alert.get("severity", "medium")
        sorted_opts = sorted(options, key=lambda x: x.get("confidence", 0), reverse=True)
        for opt in sorted_opts:
            if severity == "critical" and opt.get("risk") == "high":
                continue
            return dict(opt), [dict(o) for o in sorted_opts if o != opt]
        return dict(sorted_opts[0]), [dict(o) for o in sorted_opts[1:]]

    def _create_validation_plan(self, alert: dict, action: dict) -> list:
        base = [
            "Pod durumlarının Running olduğunu doğrula",
            "Error rate'in %5 altına düştüğünü kontrol et",
            "Latency P99'un normal seviyelere döndüğünü doğrula",
            "5 dakika izleme — yeni alert oluşmadığını onayla",
            "Downstream servis sağlık kontrolü"
        ]
        return base

    def _generate_rollback_plan(self, action: dict, service: str, namespace: str) -> str:
        return (
            f"ROLLBACK PLANI:\n"
            f"1. Eylemi geri al: kubectl rollout undo deployment/{service} -n {namespace}\n"
            f"2. Önceki stabil sürüme dön\n"
            f"3. Durumu doğrula: kubectl get pods -n {namespace}\n"
            f"4. Monitoring ekibini bilgilendir"
        )
