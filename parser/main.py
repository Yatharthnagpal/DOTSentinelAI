from dotenv import load_dotenv
load_dotenv()  # Load .env before any other imports read os.getenv()

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import shutil
import os
import json
import aiofiles
import numpy as np
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from parser.vuln_scanner import run_vulnerability_scan

# Global pipeline instance (lazy-loaded on demand to avoid blocking startup)
pipeline_instance = None

def get_pipeline():
    global pipeline_instance
    if pipeline_instance is None:
        try:
            from parser.pipeline import Pipeline
            pipeline_instance = Pipeline()
        except Exception as e:
            print(f"[!] Pipeline initialization deferred or optional dependencies missing: {e}")
            pipeline_instance = None
    return pipeline_instance

def numpy_safe(obj):
    """Recursively convert NumPy scalars and containers to native Python types."""
    if isinstance(obj, dict):
        return {str(numpy_safe(k)): numpy_safe(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple, set)):
        return [numpy_safe(i) for i in obj]
    elif isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.bool_):
        return bool(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif hasattr(obj, "to_dict"):
        return numpy_safe(obj.to_dict())
    elif hasattr(obj, "__dict__"):
        return numpy_safe(obj.__dict__)
    return obj

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[*] Starting up parser service...")
    try:
        get_pipeline()
    except Exception as e:
        print(f"[!] Pipeline load deferred: {e}")
    yield
    print("[*] Shutting down parser service...")

app = FastAPI(
    title="DOT Sentinel AI – API",
    description="Network Intrusion Detection & Vulnerability Posture Assessment Service",
    version="2.0.0",
    lifespan=lifespan
)

# Allow CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

TEMP_DIR = "temp_uploads"
os.makedirs(TEMP_DIR, exist_ok=True)


@app.get("/")
def root():
    return {
        "status": "online",
        "service": "DOT Sentinel AI Core API",
        "version": "2.0.0",
        "docs_url": "/docs",
        "health_url": "/health"
    }


# ---------------------------------------------------------------------------
# Pydantic Schemas for Vulnerability Scanner
# ---------------------------------------------------------------------------

class PasswordPolicySchema(BaseModel):
    min_length: int = 12
    requires_complexity: bool = True
    max_age_days: int = 90
    lockout_threshold: Optional[int] = 5
    check_breached_passwords: Optional[bool] = False

class FirewallRuleSchema(BaseModel):
    name: Optional[str] = "Rule"
    src: str = "any"
    dst: str = "any"
    port: Optional[int] = None
    action: str = "allow"

class InstalledAppSchema(BaseModel):
    name: str
    version: str

class VulnScanRequest(BaseModel):
    # Pillar 1: System & Software Configuration
    os_name: Optional[str] = Field(default="", description="Operating system name and version")
    installed_applications: Optional[List[InstalledAppSchema]] = Field(default=[], description="List of installed software packages and versions")
    has_unpatched_cves: Optional[bool] = Field(default=None, description="Whether known unpatched CVEs exist on the host")
    observed_ports: Optional[List[int]] = Field(default=[], description="Active TCP/UDP ports detected on the system")
    protocols_seen: Optional[List[str]] = Field(default=[], description="Network protocols observed in traffic (e.g. HTTP, SSH)")
    tls_ciphers: Optional[List[str]] = Field(default=[], description="TLS cipher suites negotiated or configured")
    disk_encryption_enabled: Optional[bool] = Field(default=None, description="Full disk encryption status (BitLocker/LUKS)")
    database_encryption_at_rest: Optional[bool] = Field(default=None, description="Database encryption at rest (TDE)")
    backup_encryption_enabled: Optional[bool] = Field(default=None, description="Backup encryption status")
    default_credentials_present: Optional[bool] = Field(default=None, description="Whether default credentials remain unchanged")
    default_secret_keys_detected: Optional[List[str]] = Field(default=[], description="List of default framework secret keys exposed")

    # Pillar 2: Identity & Access Controls
    mfa_enabled: Optional[bool] = Field(default=None, description="Multi-factor authentication globally enforced")
    mfa_enforced_for_admins: Optional[bool] = Field(default=None, description="MFA enforced for administrators")
    mfa_type: Optional[str] = Field(default="", description="Type of MFA used (e.g. app, fido2, sms)")
    password_policy: Optional[PasswordPolicySchema] = Field(default=None, description="Password complexity policy configuration")
    admin_accounts: Optional[List[str]] = Field(default=[], description="List of administrative account usernames")
    service_accounts_admin: Optional[List[str]] = Field(default=[], description="Service accounts holding administrative privileges")
    wildcard_api_keys: Optional[List[str]] = Field(default=[], description="List of unrestricted / wildcard administrative API tokens")
    stale_accounts: Optional[List[str]] = Field(default=[], description="Orphaned or inactive employee user accounts")
    dormant_service_principals: Optional[List[str]] = Field(default=[], description="Unused/dormant service accounts")

    # Pillar 3: Network & Border Defenses
    firewall_rules: Optional[List[FirewallRuleSchema]] = Field(default=[], description="Configured perimeter firewall rules")
    http_response_headers: Optional[Dict[str, str]] = Field(default={}, description="HTTP response headers emitted by the web server")
    server_banner: Optional[str] = Field(default="", description="Server identification banner string")
    stack_trace_in_errors: Optional[bool] = Field(default=False, description="Whether verbose stack traces leak in error pages")
    internal_ip_disclosed: Optional[bool] = Field(default=False, description="Whether internal IP addresses are leaked")

    # Pillar 4: Monitoring & Resilience
    siem_configured: Optional[bool] = Field(default=None, description="Centralized SIEM platform configured")
    log_types_collected: Optional[List[str]] = Field(default=[], description="Log sources ingested into SIEM")
    log_retention_days: Optional[int] = Field(default=30, description="Log retention duration in days")
    tamper_resistant_logging: Optional[bool] = Field(default=False, description="Write-once / tamper-resistant logging enabled")
    backup_configured: Optional[bool] = Field(default=None, description="System backup configured")
    backup_restore_tested: Optional[bool] = Field(default=None, description="Backups periodically tested for restoration")
    backup_offsite_or_immutable: Optional[bool] = Field(default=None, description="Backups stored offline or immutably")
    rpo_hours: Optional[int] = Field(default=None, description="Recovery Point Objective in hours")

    # Auxiliary / Flow context
    total_flows_analysed: Optional[int] = Field(default=0, description="Number of correlated network flows")
    flow_data: Optional[List[Dict[str, Any]]] = Field(default=[], description="Raw flow records from PCAP parser")


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.post("/analyze")
async def analyze_pcap(file: UploadFile = File(...)):
    if not file.filename.endswith(".pcap") and not file.filename.endswith(".pcapng"):
        raise HTTPException(status_code=400, detail="Only .pcap and .pcapng files are supported")

    file_path = os.path.join(TEMP_DIR, file.filename)
    
    try:
        # Write to file and synchronously close so it's ready for Scapy
        async with aiofiles.open(file_path, 'wb') as out_file:
            content = await file.read()
            await out_file.write(content)
            await out_file.flush()
            
        print(f"[*] Received PCAP file for analysis: {file.filename}")
        
        pipeline = get_pipeline()
        if pipeline is None:
            raise HTTPException(status_code=500, detail="Pipeline not initialized or missing dependencies")
            
        # Run pipeline
        result = pipeline.process_pcap(file_path)
        
        # Convert NumPy types to native Python so FastAPI can serialize them
        return JSONResponse(content=numpy_safe(result))
        
    except Exception as e:
        print(f"[!] Error processing file: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Cleanup
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as cleanup_err:
                print(f"[!] Warning: Could not remove temp file {file_path}: {cleanup_err}")


@app.post("/vuln-scan")
def vulnerability_scan_endpoint(payload: VulnScanRequest):
    """
    Run comprehensive vulnerability and security posture assessment across the 4 pillars.
    """
    try:
        payload_dict = payload.model_dump()
        flow_data = payload_dict.pop("flow_data", None) or []
        result = run_vulnerability_scan(payload_dict, flow_data=flow_data)
        return JSONResponse(content=result)
    except Exception as e:
        print(f"[!] Vulnerability scan error: {e}")
        raise HTTPException(status_code=500, detail=f"Vulnerability scan failed: {str(e)}")


@app.post("/vuln-scan-pcap")
async def vulnerability_scan_with_pcap(
    file: UploadFile = File(...),
    metadata: Optional[str] = Form(None)
):
    """
    Correlate a PCAP file directly with vulnerability scanning.
    Parses traffic flows and performs posture checks on discovered ports and protocols.
    """
    if not file.filename.endswith(".pcap") and not file.filename.endswith(".pcapng"):
        raise HTTPException(status_code=400, detail="Only .pcap and .pcapng files are supported")

    file_path = os.path.join(TEMP_DIR, file.filename)
    try:
        async with aiofiles.open(file_path, 'wb') as out_file:
            content = await file.read()
            await out_file.write(content)
            await out_file.flush()

        parsed_meta: Dict[str, Any] = {}
        if metadata:
            try:
                parsed_meta = json.loads(metadata)
            except Exception:
                pass

        # If pipeline is loaded, extract flows
        flows: List[Dict[str, Any]] = []
        observed_ports = set(parsed_meta.get("observed_ports", []))
        protocols_seen = set(parsed_meta.get("protocols_seen", []))

        if pipeline_instance and hasattr(pipeline_instance, "parser"):
            try:
                csv_path = os.path.join(TEMP_DIR, file.filename + ".csv")
                pipeline_instance.parser.parse_pcap_to_csv(file_path, csv_path)
                flows_df = pipeline_instance.parser.aggregate_flows(csv_path)
                if not flows_df.empty:
                    flows = flows_df.to_dict(orient="records")
                    for fl in flows:
                        dp = int(fl.get("dport", 0))
                        if dp > 0:
                            observed_ports.add(dp)
                        proto = str(fl.get("protocol", "")).upper()
                        if proto:
                            protocols_seen.add(proto)
                if os.path.exists(csv_path):
                    os.remove(csv_path)
            except Exception as parse_err:
                print(f"[!] PCAP flow correlation note: {parse_err}")

        parsed_meta["observed_ports"] = sorted(list(observed_ports))
        parsed_meta["protocols_seen"] = sorted(list(protocols_seen))
        parsed_meta["total_flows_analysed"] = len(flows)

        result = run_vulnerability_scan(parsed_meta, flow_data=flows)
        return JSONResponse(content=numpy_safe(result))

    except Exception as e:
        print(f"[!] PCAP Vulnerability scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "DOT Sentinel AI Core API",
        "model_loaded": pipeline_instance is not None,
        "vuln_scanner_enabled": True
    }
