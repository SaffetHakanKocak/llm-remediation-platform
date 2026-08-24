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
import asyncio
import time

load_dotenv(override=True)

from simulator.cloud_simulator import CloudSimulator
from simulator.remediation_agent import LLMRemediationAgent

app = FastAPI(title="AI-Powered Remediation Platform", version="1.0.0")

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


async def _run_hybrid_remediation(alert_data: dict, scenario_id: str):
    """Run a 100ms rule-based control loop while LLM supervises in background."""
    kubectl_logs = simulator.simulate_kubectl_logs(alert_data.get("source_service", ""))
    kubectl_pods = simulator.simulate_kubectl_get_pods(alert_data.get("namespace", "production"))

    started = time.time()
    llm_error = None
    control_interval_ms = 100
    min_control_ticks = 5
    max_control_ticks = 30

    rule_plan = None
    rule_handoff_context = None
    llm_task = None
    control_ticks = []
    timeline = [
        {
            "at_ms": 0,
            "phase": "alert_received",
            "label": "Alert alindi; once rule-based control-loop gecici ReAct plani uretecek.",
        }
    ]

    for tick_no in range(1, max_control_ticks + 1):
        tick_started = time.time()
        tick_plan = await asyncio.to_thread(rule_agent.analyze_and_remediate, alert_data, scenario_id)
        if rule_plan is None:
            rule_plan = tick_plan
        else:
            rule_plan = tick_plan

        tick_elapsed_ms = int((time.time() - started) * 1000)
        tick_dict = tick_plan.to_dict()
        tick_conf = tick_dict.get("confidence_score", 0)
        tick_action = tick_dict.get("selected_action", {}).get("action", "N/A")
        control_ticks.append({
            "tick": tick_no,
            "at_ms": tick_elapsed_ms,
            "interval_ms": control_interval_ms,
            "phase": "rule_control_tick",
            "confidence": tick_conf,
            "action": tick_action,
            "label": (
                f"Tick {tick_no}: rule-based gozlem ve runbook kontrolu calisti; "
                f"gecici plan guven skoru %{tick_conf * 100:.0f}."
            ),
        })

        timeline.append({
            "at_ms": tick_elapsed_ms,
            "phase": "rule_control_tick",
            "label": f"100ms control-loop tick {tick_no}: rule-based aktif kontrol calisti.",
        })

        if tick_no == 1:
            rule_handoff_context = {
                "handoff_type": "rule_trace_to_llm_supervisor",
                "control_loop_interval_ms": control_interval_ms,
                "handoff_at_ms": tick_elapsed_ms,
                "temporary_plan": tick_dict,
                "rule_react_trace": tick_dict.get("react_trace", []),
                "instruction_to_llm": (
                    "Rule-based ReAct adimlarini ve gecici plani devral; "
                    "once dogrula, sonra eksikse duzelt veya daha guvenli planla kontrolu al."
                ),
            }
            timeline.append({
                "at_ms": tick_elapsed_ms,
                "phase": "handoff_to_llm",
                "label": "Rule-based ReAct trace ve gecici plan LLM supervisor'a handoff context olarak verildi.",
            })
            llm_task = asyncio.create_task(
                asyncio.to_thread(
                    llm_agent.analyze_and_remediate,
                    alert_data,
                    scenario_id,
                    kubectl_logs,
                    kubectl_pods,
                    rule_handoff_context,
                )
            )

        if llm_task and llm_task.done() and tick_no >= min_control_ticks:
            break

        sleep_for = max(0, (control_interval_ms / 1000) - (time.time() - tick_started))
        await asyncio.sleep(sleep_for)

    rule_ready_ms = control_ticks[0]["at_ms"] if control_ticks else int((time.time() - started) * 1000)

    try:
        llm_plan = await llm_task if llm_task else None
    except Exception as e:
        llm_plan = None
        llm_error = str(e)
    llm_ready_ms = int((time.time() - started) * 1000)

    rule_dict = rule_plan.to_dict()
    rule_dict["_mode"] = "rule-based"

    if llm_plan:
        llm_dict = llm_plan.to_dict()
        llm_dict["_mode"] = "llm"
    else:
        llm_dict = None

    rule_conf = rule_dict.get("confidence_score", 0)
    llm_conf = llm_dict.get("confidence_score", 0) if llm_dict else 0
    rule_command = rule_dict.get("selected_action", {}).get("command", "")
    llm_command = llm_dict.get("selected_action", {}).get("command", "") if llm_dict else ""

    if llm_error:
        final_plan = dict(rule_dict)
        takeover = False
        decision_reason = "LLM sonucu alinamadi; rule-based plan aktif planda tutuldu."
    elif llm_conf >= max(0.50, rule_conf - 0.05):
        final_plan = dict(llm_dict)
        takeover = True
        decision_reason = "LLM analizi yeterli guven skoruna ulasti ve kontrol LLM planina devredildi."
    else:
        final_plan = dict(rule_dict)
        takeover = False
        decision_reason = "Rule-based plan daha yuksek guven skorunda kaldigi icin kontrol devredilmedi."

    final_plan["_mode"] = "hybrid"
    final_plan["_source_mode"] = "llm" if takeover else "rule-based"

    timeline.extend([
        {
            "at_ms": llm_ready_ms,
            "phase": "llm_ready" if not llm_error else "llm_error",
            "label": "LLM supervisor derin analiz sonucunu uretti." if not llm_error else "LLM hata verdi; rule-based loop fallback olarak kaldi.",
        },
        {
            "at_ms": llm_ready_ms,
            "phase": "takeover" if takeover else "rule_retained",
            "label": "Kontrol LLM planina devredildi." if takeover else "Rule-based plan aktif kaldi.",
        },
    ])

    return {
        "initial_plan": rule_dict,
        "llm_plan": llm_dict,
        "final_plan": final_plan,
        "timeline": timeline,
        "handoff_context": {
            "handoff_at_ms": rule_handoff_context.get("handoff_at_ms") if rule_handoff_context else None,
            "temporary_action": rule_handoff_context.get("temporary_plan", {}).get("selected_action", {}) if rule_handoff_context else {},
            "react_steps_sent": len(rule_handoff_context.get("rule_react_trace", [])) if rule_handoff_context else 0,
            "instruction": rule_handoff_context.get("instruction_to_llm") if rule_handoff_context else "",
        },
        "control_loop": {
            "interval_ms": control_interval_ms,
            "ticks": control_ticks,
            "tick_count": len(control_ticks),
            "stopped_by": "llm_ready" if llm_task and llm_task.done() and len(control_ticks) < max_control_ticks else "max_ticks",
        },
        "decision": {
            "takeover": takeover,
            "final_source": "llm" if takeover else "rule-based",
            "reason": decision_reason,
            "llm_error": llm_error,
        },
        "comparison": {
            "rule_based_time_ms": rule_ready_ms,
            "llm_time_ms": llm_ready_ms,
            "rule_based_confidence": rule_conf,
            "llm_confidence": llm_conf,
            "same_action": bool(rule_command and rule_command == llm_command),
        },
    }


@app.post("/api/remediate")
async def run_remediation(payload: dict):
    """Alert verisi üzerinde seçilen modda remediation agent'ını çalıştırır."""
    alert_data = payload.get("alert", {})
    scenario_id = payload.get("scenario_id")
    mode = payload.get("mode", "llm")

    kubectl_logs = simulator.simulate_kubectl_logs(alert_data.get("source_service", ""))
    kubectl_pods = simulator.simulate_kubectl_get_pods(alert_data.get("namespace", "production"))

    if mode == "hybrid":
        return JSONResponse(content=await _run_hybrid_remediation(alert_data, scenario_id))

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


@app.post("/api/remediate/hybrid")
async def hybrid_remediation(payload: dict):
    """Rule-based fast path ile baslar, LLM sonucu hazir olunca karar verir."""
    alert_data = payload.get("alert", {})
    scenario_id = payload.get("scenario_id")
    return JSONResponse(content=await _run_hybrid_remediation(alert_data, scenario_id))


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
    submitted_plan = payload.get("plan")

    if submitted_plan:
        selected = submitted_plan.get("selected_action", {})
        validation_steps = submitted_plan.get("validation_steps", [])
        result = {
            "success": True,
            "plan_id": submitted_plan.get("id", "submitted-plan"),
            "action_executed": selected.get("action", "N/A"),
            "command_executed": selected.get("command", "N/A"),
            "execution_time_ms": round(time.time() * 1000) % 5000 + 500,
            "validation_results": [
                {"step": step, "passed": True} for step in validation_steps
            ],
            "status": "completed",
            "completed_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        return JSONResponse(content={
            "plan": submitted_plan,
            "execution": result,
            "simulation_result": simulator.simulate_remediation_result(
                scenario_id, selected.get("action", "N/A")
            ) if scenario_id else None
        })

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
