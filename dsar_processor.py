"""
GDPR DSAR Processor - FastAPI Backend with OpenAI
Handles: Deduplication, PII Classification, Data Aggregation
Includes: Integrated Approval Dashboard
"""
from typing import Optional
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Dict, Any
import json
import logging
from datetime import datetime
from collections import defaultdict
import openai
import os
from dotenv import load_dotenv
import hashlib

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="GDPR DSAR Processor",
    description="Deduplication and PII Classification for GDPR Data Subject Access Requests",
    version="1.0.0"
)

# Initialize OpenAI client
openai.api_key = os.getenv("OPENAI_API_KEY")

# DATA MODELS


class ProcessDSARRequest(BaseModel):
    dsar_id: str
    email: str
    name: str
    extracted_data: List[Dict[str, Any]]


class ProcessedRecord(BaseModel):
    canonical_id: str
    systems: List[str]
    raw_data: Dict[str, Any]
    pii_fields: Dict[str, str]
    pii_count: int
    category: str


class ProcessDSARResponse(BaseModel):
    dsar_id: str
    status: str
    total_records_extracted: int
    total_records_deduplicated: int
    pii_summary: Dict[str, int]
    data_by_category: Dict[str, List[ProcessedRecord]]
    processed_at: str
    # Make it optional with None as default
    error_message: Optional[str] = None


# DEDUPLICATION


def create_canonical_id(record_data: Dict[str, Any]) -> str:
    key_fields = []
    for field in ["email", "id", "firstname", "lastname", "subject", "date"]:
        if field in record_data and record_data[field]:
            key_fields.append(str(record_data[field]).lower().strip())
    canonical_string = "|".join(key_fields)
    return hashlib.md5(canonical_string.encode()).hexdigest()[:16]


def deduplicate_records(extracted_data: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    deduplicated = {}
    for record in extracted_data:
        system_name = record.get("system_name", "unknown")
        try:
            if isinstance(record.get("data_json"), str):
                data_list = json.loads(record["data_json"])
            else:
                data_list = record.get("data_json", [])
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse data_json for {system_name}")
            data_list = []

        for item in data_list:
            canonical_id = create_canonical_id(item)
            if canonical_id not in deduplicated:
                deduplicated[canonical_id] = {
                    "systems": [],
                    "raw_data": item,
                    "all_versions": []
                }
            if system_name not in deduplicated[canonical_id]["systems"]:
                deduplicated[canonical_id]["systems"].append(system_name)
            deduplicated[canonical_id]["all_versions"].append({
                "system": system_name,
                "data": item
            })
    return deduplicated

# PII CLASSIFICATION WITH OPENAI


def classify_pii_with_openai(record: Dict[str, Any], dsar_email: str) -> Dict[str, str]:
    try:
        record_json = json.dumps(record, indent=2)[:2000]
        prompt = f"""Classify PII fields in this record.
Data Subject Email: {dsar_email}
Record: {record_json}
Respond with JSON only: {{"field_name": "pii_type"}}
PII types: email_address, phone_number, name, date_of_birth, address, ssn, passport, credit_card, ip_address, user_id, other
Only include PII fields. If none found, return {{}}."""

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a GDPR PII classification expert. Respond only with valid JSON."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=500,
            temperature=0.2
        )

        response_text = response.choices[0].message.content
        start = response_text.find("{")
        end = response_text.rfind("}") + 1
        if start != -1 and end > start:
            json_str = response_text[start:end]
            return json.loads(json_str)
        return {}
    except Exception as e:
        logger.error(f"Error classifying PII: {str(e)}")
        return {}


def categorize_record(record: Dict[str, Any], pii_fields: Dict[str, str]) -> str:
    record_json = json.dumps(record).lower()
    if "subject" in record and "from" in record and "body" in record:
        return "email"
    elif "ticket" in record_json or "support" in record_json:
        return "support"
    elif "contact" in record_json or "firstname" in record:
        return "contact"
    elif "invoice" in record_json or "order" in record_json or "payment" in record_json:
        return "transaction"
    elif "user" in record_json or "account" in record_json:
        return "user"
    else:
        return "other"

# MAIN ENDPOINT


@app.post("/process-dsar", response_model=ProcessDSARResponse)
async def process_dsar(request: ProcessDSARRequest) -> ProcessDSARResponse:
    logger.info(f"Processing DSAR: {request.dsar_id} for {request.email}")
    try:
        # Extract all records
        all_records = []
        total_extracted = 0
        for extracted_item in request.extracted_data:
            try:
                if isinstance(extracted_item.get("data_json"), str):
                    data_list = json.loads(extracted_item["data_json"])
                else:
                    data_list = extracted_item.get("data_json", [])
                all_records.extend(data_list)
                total_extracted += extracted_item.get(
                    "record_count", len(data_list))
            except Exception as e:
                logger.warning(f"Error processing extracted data: {str(e)}")
                continue

        logger.info(f"Total records extracted: {total_extracted}")

        # Deduplicate
        deduplicated = deduplicate_records(request.extracted_data)
        total_deduplicated = len(deduplicated)

        logger.info(f"Total deduplicated: {total_deduplicated}")

        # Classify PII and categorize
        pii_summary = defaultdict(int)
        data_by_category = defaultdict(list)

        for canonical_id, record_info in deduplicated.items():
            raw_data = record_info["raw_data"]
            systems = record_info["systems"]
            pii_fields = classify_pii_with_openai(raw_data, request.email)

            for field_name, pii_type in pii_fields.items():
                pii_summary[pii_type] += 1

            category = categorize_record(raw_data, pii_fields)
            processed = ProcessedRecord(
                canonical_id=canonical_id,
                systems=systems,
                raw_data=raw_data,
                pii_fields=pii_fields,
                pii_count=len(pii_fields),
                category=category
            )
            data_by_category[category].append(processed)

        response = ProcessDSARResponse(
            dsar_id=request.dsar_id,
            status="success",
            total_records_extracted=total_extracted,
            total_records_deduplicated=total_deduplicated,
            pii_summary=dict(pii_summary),
            data_by_category={k: v for k, v in data_by_category.items()},
            processed_at=datetime.utcnow().isoformat(),
            error_message=None
        )
        logger.info(f"DSAR {request.dsar_id} processed successfully")
        return response
    except Exception as e:
        logger.error(f"Error processing DSAR {request.dsar_id}: {str(e)}")
        return ProcessDSARResponse(
            dsar_id=request.dsar_id,
            status="error",
            total_records_extracted=0,
            total_records_deduplicated=0,
            pii_summary={},
            data_by_category={},
            processed_at=datetime.utcnow().isoformat(),
            error_message=str(e)
        )

# HEALTH CHECK


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "GDPR DSAR Processor"
    }


# DASHBOARD ROUTES - Static Files

# Mount static files (dashboard)
if os.path.exists("static"):
    app.mount("/dashboard", StaticFiles(directory="static",
              html=True), name="static")
    logger.info("Dashboard mounted at /dashboard")


@app.get("/")
async def root():
    """Serve dashboard homepage"""
    if os.path.exists("static/index.html"):
        return FileResponse("static/index.html")
    else:
        return {
            "message": "GDPR DSAR Processor API",
            "version": "1.0.0",
            "endpoints": {
                "health": "/health",
                "process_dsar": "/process-dsar",
                "dashboard": "/dashboard or /"
            }
        }


@app.get("/api/status")
async def api_status():
    """API Status endpoint for dashboard"""
    return {
        "status": "online",
        "service": "GDPR DSAR Processor",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    logger.info(f"Starting DSAR Processor on {host}:{port}")
    logger.info("Dashboard available at http://localhost:{port}/")
    uvicorn.run(app, host=host, port=port, log_level="info")
