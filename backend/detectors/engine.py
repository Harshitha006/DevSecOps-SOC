import uuid
import re
from .rules import RULES
try:
    from backend.models import Incident
except ImportError:
    from ..models import Incident


def scan_event(event, db):
    incidents = []

    if not event.files:
        return []

    for file in event.files:
        path = file.get("path", "")
        content = file.get("content", "")

        for rule in RULES:
            matches = re.findall(rule["pattern"], content)

            for match in matches:
                incident = Incident(
                    id=str(uuid.uuid4()),
                    event_id=event.id,
                    repo=event.repo,
                    file_path=path,
                    rule_name=rule["name"],
                    severity=rule["severity"],
                    match=str(match)
                )

                db.add(incident)
                incidents.append(incident)

    db.commit()
    return incidents
