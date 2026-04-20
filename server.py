"""
FastAPI Backend — LLM-Based Remediation Dashboard API
Tüm simulation ve agent endpointlerini sağlar.
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os

load_dotenv(override=True)

from simulator.cloud_simulator import CloudSimulator
from simulator.remediation_agent import LLMRemediationAgent

app = FastAPI(title="LLM-Based Remediation Platform", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
llm_mode = os.getenv("LLM_MODE", "simulation")
simulator = CloudSimulator()
agent = LLMRemediationAgent(mode=llm_mode)

# Static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
async def serve_dashboard():
    index_path = os.path.join(static_dir, "index.html")
    return FileResponse(index_path)


@app.get("/api/cluster/status")
async def get_cluster_status():
    """Cluster genel durumunu döndürür."""
    return JSONResponse(content=simulator.cluster_state)


@app.get("/api/scenarios")
async def list_scenarios():
    """Mevcut incident senaryolarını listeler."""
    return JSONResponse(content=simulator.list_scenarios())


@app.post("/api/simulate/{scenario_id}")
async def simulate_incident(scenario_id: str):
    """Bir incident senaryosu simüle eder ve alert üretir."""
    try:
        alert = simulator.generate_alert(scenario_id)
        return JSONResponse(content=alert.to_dict())
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=404)


@app.post("/api/simulate/random/trigger")
async def simulate_random_incident():
    """Rastgele bir incident simüle eder."""
    alert = simulator.generate_alert()
    return JSONResponse(content=alert.to_dict())


rule_agent = LLMRemediationAgent(mode="simulation")
llm_agent = LLMRemediationAgent(mode="llm")


@app.post("/api/remediate")
async def run_remediation(payload: dict):
    """Alert verisi üzerinde seçilen modda remediation agent'ını çalıştırır."""
    alert_data = payload.get("alert", {})
    scenario_id = payload.get("scenario_id")
    mode = payload.get("mode", "llm")

    kubectl_logs = simulator.simulate_kubectl_logs(alert_data.get("source_service", ""))
    kubectl_pods = simulator.simulate_kubectl_get_pods(alert_data.get("namespace", "production"))

    if mode == "rule-based":
        plan = rule_agent.analyze_and_remediate(alert_data, scenario_id)
        plan_dict = plan.to_dict()
        plan_dict["_mode"] = "rule-based"
        return JSONResponse(content=plan_dict)

    try:
        plan = llm_agent.analyze_and_remediate(
            alert_data, scenario_id,
            kubectl_logs=kubectl_logs,
            kubectl_pods=kubectl_pods
        )
        plan_dict = plan.to_dict()
        plan_dict["_mode"] = "llm"
        return JSONResponse(content=plan_dict)
    except Exception as e:
        plan = rule_agent.analyze_and_remediate(alert_data, scenario_id)
        plan_dict = plan.to_dict()
        plan_dict["_mode"] = "llm"
        plan_dict["_fallback"] = True
        plan_dict["_llm_error"] = str(e)
        return JSONResponse(content=plan_dict)


@app.post("/api/remediate/compare")
async def compare_remediation(payload: dict):
    """Aynı alert için hem rule-based hem LLM-based analiz çalıştırıp karşılaştırır."""
    import time as _time
    alert_data = payload.get("alert", {})
    scenario_id = payload.get("scenario_id")

    kubectl_logs = simulator.simulate_kubectl_logs(alert_data.get("source_service", ""))
    kubectl_pods = simulator.simulate_kubectl_get_pods(alert_data.get("namespace", "production"))

    t0 = _time.time()
    rule_plan = rule_agent.analyze_and_remediate(alert_data, scenario_id)
    rule_time_ms = int((_time.time() - t0) * 1000)

    llm_error = None
    t1 = _time.time()
    try:
        llm_plan = llm_agent.analyze_and_remediate(
            alert_data, scenario_id,
            kubectl_logs=kubectl_logs,
            kubectl_pods=kubectl_pods
        )
    except Exception as e:
        llm_plan = rule_plan
        llm_error = str(e)
    llm_time_ms = int((_time.time() - t1) * 1000)

    rule_dict = rule_plan.to_dict()
    rule_dict["_mode"] = "rule-based"
    llm_dict = llm_plan.to_dict()
    llm_dict["_mode"] = "llm"
    if llm_error:
        llm_dict["_llm_error"] = llm_error

    rule_rc = rule_dict.get("root_cause_analysis", "").lower()
    llm_rc = llm_dict.get("root_cause_analysis", "").lower()
    rule_cmd = rule_dict.get("selected_action", {}).get("command", "")
    llm_cmd = llm_dict.get("selected_action", {}).get("command", "")

    return JSONResponse(content={
        "rule_based": rule_dict,
        "llm_based": llm_dict,
        "comparison": {
            "rule_based_time_ms": rule_time_ms,
            "llm_time_ms": llm_time_ms,
            "rule_based_confidence": rule_dict.get("confidence_score", 0),
            "llm_confidence": llm_dict.get("confidence_score", 0),
            "rule_based_steps": len(rule_dict.get("react_trace", [])),
            "llm_steps": len(llm_dict.get("react_trace", [])),
            "same_root_cause": any(w in llm_rc for w in rule_rc.split()[:5]) if rule_rc and llm_rc else False,
            "same_action": rule_cmd == llm_cmd,
            "llm_error": llm_error
        }
    })


@app.post("/api/execute")
async def execute_remediation(payload: dict):
    """Onaylanmış remediation planını çalıştırır."""
    alert_data = payload.get("alert", {})
    scenario_id = payload.get("scenario_id")
    plan = agent.analyze_and_remediate(alert_data, scenario_id)
    result = agent.execute_plan(plan)
    return JSONResponse(content={
        "plan": plan.to_dict(),
        "execution": result,
        "simulation_result": simulator.simulate_remediation_result(
            scenario_id, plan.selected_action.get("action", "N/A")
        ) if scenario_id else None
    })


@app.get("/api/logs/{scenario_id}")
async def get_simulated_logs(scenario_id: str):
    """Senaryo için simüle edilmiş logları döndürür."""
    try:
        alert = simulator.generate_alert(scenario_id)
        logs = simulator.simulate_kubectl_logs(alert.source_service)
        pods = simulator.simulate_kubectl_get_pods(alert.namespace)
        return JSONResponse(content={
            "logs": logs,
            "pods": pods,
            "alert": alert.to_dict()
        })
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=404)


@app.get("/api/history")
async def get_remediation_history():
    """Geçmiş remediation planlarını döndürür."""
    return JSONResponse(content=agent.history)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8765)
