from fastapi import FastAPI, Depends, Request
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
import hashlib
import json

try:
    from . import models, config
except ImportError:
    import models
    import config

# Initialize FastAPI app
app = FastAPI(title="DevSecOps SOC Assistant")

# Create database tables
models.Base.metadata.create_all(bind=config.engine)

# DB dependency
def get_db():
    db = config.SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/webhooks/github")
async def github_webhook(request: Request, db: Session = Depends(get_db)):
    # Read raw body ONCE
    body = await request.body()

    print("\n--- GitHub Webhook Received ---")
    print(f"Raw body: {body.decode('utf-8', errors='replace')}")

    # Parse JSON safely
    try:
        payload = json.loads(body)
        print(f"Parsed payload: {payload}")
    except Exception as e:
        print(f"JSON Parse Error: {e}")
        payload = {}

    # Extract repo
    repo_obj = payload.get("repository", {})
    repo = repo_obj.get("full_name", "unknown") if isinstance(repo_obj, dict) else "unknown"

    # Extract branch
    ref = payload.get("ref", "")
    branch = ref.split("/")[-1] if ref else "unknown"

    # Event type (prefer header)
    event_type = request.headers.get("X-GitHub-Event", payload.get("event_type", "unknown"))

    # Unique event ID
    event_id = request.headers.get("X-GitHub-Delivery")
    if not event_id:
        body_hash = hashlib.sha256(body).hexdigest()[:16]
        event_id = f"{event_type}_{body_hash}"

    print(f"Repo: {repo}, Branch: {branch}, Event: {event_type}, ID: {event_id}")

    # Dedup (fast check)
    existing = db.query(models.Event).filter(models.Event.id == event_id).first()
    if existing:
        return {
            "message": "duplicate event ignored",
            "event_id": event_id
        }

    # Create event object
    new_event = models.Event(
        id=event_id,
        event_type=event_type,
        raw_payload=payload,
        repo=repo,
        branch=branch
    )

    # DB insert with safety (handles race conditions)
    try:
        db.add(new_event)
        db.commit()
    except IntegrityError:
        db.rollback()
        return {
            "message": "duplicate event ignored",
            "event_id": event_id
        }

    return {
        "received": True,
        "event_id": event_id,
        "repo": repo,
        "branch": branch
    }


@app.get("/events")
def get_events(db: Session = Depends(get_db)):
    return db.query(models.Event).all()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)