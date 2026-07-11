from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
import logging
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional

logger = logging.getLogger("AgentSentry.Webhooks")
router = APIRouter()

# Forward declaration for agent execution scheduler
_agent_runner = None

def register_agent_runner(runner_fn):
    """
    Registers the orchestrator execution function that handles PR validation.
    """
    global _agent_runner
    _agent_runner = runner_fn
    logger.info("Agent runner pipeline registered successfully with Webhook Router.")

class ProjectSchema(BaseModel):
    id: int
    name: str
    web_url: str = Field(alias="web_url")

class MergeRequestAttributes(BaseModel):
    id: int
    iid: int
    title: str
    source_branch: str = Field(alias="source_branch")
    target_branch: str = Field(alias="target_branch")
    source_project_id: int = Field(alias="source_project_id")
    target_project_id: int = Field(alias="target_project_id")
    action: str
    state: str
    last_commit: Dict[str, Any] = Field(alias="last_commit")

class GitLabMRPayload(BaseModel):
    object_kind: str = Field(alias="object_kind")
    event_type: str = Field(alias="event_type")
    project: ProjectSchema
    object_attributes: MergeRequestAttributes = Field(alias="object_attributes")

@router.post("/gitlab")
async def gitlab_webhook(
    request: Request,
    payload: Dict[str, Any],
    background_tasks: BackgroundTasks
):
    """
    FastAPI endpoint receiving GitLab events.
    """
    # Verify event header
    event_header = request.headers.get("X-Gitlab-Event")
    if not event_header:
        logger.warning("Rejected webhook request: Missing X-Gitlab-Event header")
        raise HTTPException(status_code=400, detail="Missing X-Gitlab-Event header")
        
    logger.info(f"Received GitLab Webhook event type: {event_header}")
    
    if event_header != "Merge Request Hook":
        return {"status": "ignored", "reason": f"Unsupported event type: {event_header}"}

    try:
        parsed_payload = GitLabMRPayload(**payload)
        attrs = parsed_payload.object_attributes
        
        logger.info(
            f"Processing MR iid={attrs.iid} | Action: {attrs.action} | Title: {attrs.title}"
        )
        
        if attrs.action in ["open", "reopen", "update"]:
            if _agent_runner:
                background_tasks.add_task(
                    _agent_runner,
                    project_id=parsed_payload.project.id,
                    mr_iid=attrs.iid,
                    source_branch=attrs.source_branch,
                    target_branch=attrs.target_branch,
                    last_commit_sha=attrs.last_commit["id"]
                )
                return {
                    "status": "triggered",
                    "project": parsed_payload.project.name,
                    "mr_iid": attrs.iid,
                    "action": attrs.action
                }
            else:
                logger.error("Agent runner is not registered in the webhook controller.")
                return {"status": "failed", "reason": "Agent execution pipeline offline."}
        else:
            return {"status": "ignored", "reason": f"MR action '{attrs.action}' ignored."}
            
    except Exception as e:
        logger.error(f"Error parsing GitLab webhook payload: {str(e)}")
        raise HTTPException(status_code=422, detail=f"Unprocessable Entity: {str(e)}")
