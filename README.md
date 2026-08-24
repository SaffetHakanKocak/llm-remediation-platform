# AI-Powered Remediation Platform

Kubernetes ve bulut altyapısı incident'larını gerçek bir cluster'a ihtiyaç duymadan analiz etmek için geliştirilmiş, FastAPI tabanlı bir AIOps simülasyon platformudur. Uygulama; alert üretimi, ReAct tabanlı kök neden analizi, risk değerlendirmesi ve remediation planı oluşturma adımlarını tek bir dashboard üzerinden gösterir.

> **Durum:** Bu proje bir simülasyon ve prototipleme platformudur. Üretim Kubernetes cluster'ına bağlanmaz; ekranda gösterilen `kubectl` komutları simüle edilir ve uygulanmış gibi raporlanır.

## Öne Çıkan Özellikler

- 22 gerçekçi Kubernetes incident senaryosu
- Rastgele veya seçili senaryo üzerinden dinamik alert üretimi
- ReAct (Reasoning + Acting) izinin görselleştirilmesi
- Rule-based, LLM-based, hibrit ve karşılaştırma modları
- Hibrit modda 100 ms kural tabanlı fast-path ve arka planda LLM supervisor handoff'u
- Çok faktörlü güven skoru: semptom eşleşmesi, metrik anomalisi, runbook kapsamı, kanıt zenginliği ve aksiyon özgüllüğü
- Simüle edilmiş `kubectl logs`, pod listesi ve remediation sonucu
- LLM sağlayıcısı olarak Groq veya OpenAI Chat Completions desteği
- Onaylanan planın simüle edilmiş yürütülmesi ve doğrulama adımları

## Mimari

```text
Browser Dashboard (static/)
	|
	| HTTP / JSON
	v
FastAPI API (server.py)
	|
	+--> CloudSimulator
	|      Alert, pod, log ve cluster durumu üretir
	|
	+--> LLMRemediationAgent
	       Rulebook analizi veya Groq/OpenAI LLM çağrısı
```

### Dizin Yapısı

```text
.
├── server.py                         # FastAPI uygulaması ve API endpoint'leri
├── simulator/
│   ├── cloud_simulator.py             # Cluster, incident, alert ve kubectl simülasyonu
│   └── remediation_agent.py           # Runbook, ReAct ve LLM remediation motoru
└── static/
    ├── index.html                     # Dashboard arayüzü
    ├── app.js                         # API istemcisi ve UI akışı
    └── style.css                      # Dashboard tasarımı
```

## Gereksinimler

- Python 3.10 veya üzeri
- Simülasyon modu için internet bağlantısı gerekmez
- LLM modu için Groq veya OpenAI API anahtarı

Projede henüz `requirements.txt` bulunmadığı için bağımlılıkları aşağıdaki komutla kurun:

```bash
python -m pip install fastapi uvicorn python-dotenv requests
```

Windows'ta `python` komutu bulunamıyorsa aynı komutları `py -m pip` ve `py server.py` ile çalıştırabilirsiniz.

## Çalıştırma

Proje kök dizininde:

```bash
python server.py
```

Sunucu varsayılan olarak `http://127.0.0.1:8765` adresinde başlar. Dashboard'u tarayıcıda açın:

```text
http://127.0.0.1:8765
```

Alternatif olarak Uvicorn ile:

```bash
uvicorn server:app --host 127.0.0.1 --port 8765 --reload
```

## Yapılandırma

Varsayılan akış simülasyon tabanlıdır. Gerçek LLM analizi için proje kökünde `.env` dosyası oluşturun. `.env` dosyası `.gitignore` içinde olduğu için API anahtarlarını kaynak koda yazmayın.

### Groq

```dotenv
LLM_MODE=llm
LLM_PROVIDER=groq
GROQ_API_KEY=your_groq_api_key
GROQ_MODEL=llama-3.3-70b-versatile
```

### OpenAI

```dotenv
LLM_MODE=llm
LLM_PROVIDER=openai
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-4o-mini
```

LLM API anahtarı tanımlı değilse `/api/remediate` endpoint'i hata durumunda rule-based planı fallback olarak döndürür. Gerçek LLM çağrısı `requests` ile yapılır ve 45 saniyelik timeout kullanır.

## Çalışma Modları

| Mod | Açıklama |
| --- | --- |
| `rule-based` | Yerleşik runbook bilgi tabanından hızlı ve deterministik plan üretir. |
| `llm` | Alert, metrikler, pod bilgisi ve simüle logları LLM'e göndererek ReAct planı üretir. |
| `hybrid` | Rule-based fast-path'i hemen başlatır; LLM sonucu geldiğinde kontrolü güven skoruna göre devreder veya mevcut planı korur. |
| `compare` | Aynı alert için rule-based ve LLM planlarını süre, güven skoru, kök neden ve aksiyon bakımından karşılaştırır. |

## API Referansı

| Method | Endpoint | Açıklama |
| --- | --- | --- |
| `GET` | `/api/cluster/status` | Simüle cluster durumunu döndürür. |
| `GET` | `/api/scenarios` | Kullanılabilir incident senaryolarını listeler. |
| `POST` | `/api/simulate/{scenario_id}` | Seçili senaryo için alert üretir. |
| `POST` | `/api/simulate/random/trigger` | Rastgele bir incident alert'i üretir. |
| `POST` | `/api/remediate` | Seçilen moda göre remediation planı üretir. |
| `POST` | `/api/remediate/hybrid` | Hibrit fast-path ve LLM handoff akışını çalıştırır. |
| `POST` | `/api/remediate/compare` | İki analiz yaklaşımını karşılaştırır. |
| `POST` | `/api/execute` | Gönderilen planı simüle ederek yürütür. |
| `GET` | `/api/logs/{scenario_id}` | Senaryonun simüle loglarını ve pod çıktısını döndürür. |
| `GET` | `/api/history` | Agent geçmişini döndürür. |

### Remediation İsteği Örneği

Önce bir alert üretip dönen JSON'u `/api/remediate` endpoint'ine gönderin:

```bash
curl -X POST http://127.0.0.1:8765/api/simulate/oom_kill_memory_leak
```

```json
{
  "alert": { "id": "ALT-...", "title": "...", "metrics": {} },
  "scenario_id": "oom_kill_memory_leak",
  "mode": "rule-based"
}
```

Yanıt; `root_cause_analysis`, `confidence_score`, `selected_action`, `alternative_actions`, `rollback_plan`, `validation_steps` ve `react_trace` alanlarını içerir.

## Analiz Akışı

1. Simulator seçili veya rastgele incident için metrikleri randomize ederek alert oluşturur.
2. Agent alert'i runbook semptomlarıyla eşleştirir ve altyapı kanıtlarını inceler.
3. Kök neden ve risk seviyesi değerlendirilir.
4. En uygun aksiyon, alternatifler, rollback planı ve doğrulama adımları oluşturulur.
5. Kullanıcı planı onayladığında yürütme ve sonuç doğrulaması simüle edilir.

Rule-based bilgi tabanında eşleşmeyen senaryolar, LLM modunun bilinmeyen anomalilerdeki farkını göstermek için özellikle bulunur.

## Güvenlik ve Sınırlar

- API anahtarlarını `.env` içinde tutun ve kesinlikle commit etmeyin.
- CORS şu anda tüm origin'lere açıktır (`*`); üretim kullanımı için izin verilen origin'leri sınırlandırın.
- `/api/execute` gerçek komut çalıştırmaz; sonuçlar simülasyondur.
- LLM çıktıları doğrudan üretim ortamında uygulanmadan önce insan onayı, komut incelemesi ve uygun erişim kontrolleri gerekir.
- Uygulama kalıcı bir veritabanı kullanmaz; cluster ve agent geçmişi proses belleğinde tutulur ve yeniden başlatmada silinir.

