import os
import time
import hmac
import uuid
import hashlib
import json
import logging
from fastapi import FastAPI, Depends, Request, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
# API_KEY=1234567890
try:
    from . import models, config
except ImportError:
    import models
    import config

# Configure structured logging
logging.basicConfig(
    level=logging.DEBUG if os.getenv("DEBUG", "False").lower() in ("true", "1", "yes") else logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("webhook_handler")

app = FastAPI(title="DevSecOps SOC Assistant")

models.Base.metadata.create_all(bind=config.engine)

def get_db():
    db = config.SessionLocal()
    try:
        yield db
    finally:
        db.close()

GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")

def verify_signature(payload_body: bytes, signature_header: str) -> bool:
    """Verify that the payload was sent from GitHub by validating SHA256 signature."""
    if not signature_header:
        return False
    
    hash_object = hmac.new(
        GITHUB_WEBHOOK_SECRET.encode("utf-8"),
        msg=payload_body,
        digestmod=hashlib.sha256
    )
    expected_signature = "sha256=" + hash_object.hexdigest()
    
    return hmac.compare_digest(expected_signature, signature_header)

@app.post("/webhooks/github")
async def github_webhook(request: Request, db: Session = Depends(get_db)):
    start_time = time.time()
    logger.info("Received GitHub webhook request")
    
    # 1. Read raw body
    try:
        body = await request.body()
    except Exception as e:
        logger.error(f"Failed to read request body: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to read body")

    # 2. Strict Signature Verification
    if not GITHUB_WEBHOOK_SECRET:
        logger.error("GITHUB_WEBHOOK_SECRET not configured. Rejecting request for security.")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Server misconfiguration")

    signature = request.headers.get("X-Hub-Signature-256", "")
    if not verify_signature(body, signature):
        logger.warning("Invalid GitHub webhook signature")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid signature")
    
    logger.info("Signature validation: SUCCESS")

    # 3. Parse JSON Payload securely
    try:
        payload = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        logger.warning("Failed to parse JSON payload")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON payload")

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"Full webhook payload: {json.dumps(payload)}")

    # 4. Extract Event Metadata
    event_type = request.headers.get("X-GitHub-Event", "unknown")
    
    # Optional filtering (e.g. only process push and pull_request)
    if event_type not in ["push", "pull_request"]:
        logger.info(f"Ignoring irrelevant event type: {event_type}")
        return {"status": "ignored"}
    
    # Extract Repo
    repo_obj = payload.get("repository", {})
    repo = repo_obj.get("full_name") if isinstance(repo_obj, dict) else None

    # Extract Branch (only if it starts with refs/heads/)
    ref = payload.get("ref", "")
    branch = ref.split("/")[-1] if ref.startswith("refs/heads/") else None

    logger.info(f"Event metadata - Type: {event_type}, Repo: {repo}, Branch: {branch}")

    # 5. Replay Protection using Delivery ID
    delivery_id = request.headers.get("X-GitHub-Delivery")
    if not delivery_id:
        delivery_id = str(uuid.uuid4())
        logger.debug(f"No delivery ID found, generated fallback: {delivery_id}")

    existing = db.query(models.Event).filter(models.Event.id == delivery_id).first()
    if existing:
        logger.info(f"Duplicate webhook ignored (Delivery ID: {delivery_id})")
        return {"status": "duplicate"}

    # 6. Store in Database
    new_event = models.Event(
        id=delivery_id,
        event_type=event_type,
        raw_payload=payload,
        repo=repo,
        branch=branch
    )

    try:
        db.add(new_event)
        db.commit()
        logger.info(f"Successfully inserted webhook event into database (ID: {delivery_id})")
    except IntegrityError as e:
        db.rollback()
        logger.warning(f"IntegrityError during database insert (possible duplicate race condition): {str(e)}")
        return {"status": "duplicate"}
    except Exception as e:
        db.rollback()
        logger.error(f"Unexpected error during database insert: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal database error")

    logger.debug(f"Processing time: {time.time() - start_time:.4f}s")
    
    return {"status": "success"}

@app.get("/events")
def get_events(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """Fetch recent webhook events with pagination."""
    return db.query(models.Event).order_by(models.Event.created_at.desc()).offset(skip).limit(limit).all()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)