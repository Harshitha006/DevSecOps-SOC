import uuid
import re
from .rules import RULES
try:
    from .models import Incident
except ImportError:
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from models import Incident


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
