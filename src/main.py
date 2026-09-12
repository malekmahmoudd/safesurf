"""HTTP entry point for the SafeSurf web product."""

from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, HttpUrl

from src.workflow import build_graph

load_dotenv()
app = FastAPI(title="SafeSurf", version="1.0.0")
graph = build_graph()
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


class CheckRequest(BaseModel):
    website_url: HttpUrl
    user_request: str = Field(min_length=1, max_length=1000)
    history: list[dict[str, str]] = Field(default_factory=list, max_length=12)


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(static_dir / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/check")
def check_website(payload: CheckRequest) -> dict[str, str]:
    try:
        result = graph.invoke({"website_url": str(payload.website_url), "user_request": payload.user_request.strip(), "history": payload.history})
    except Exception as error:
        raise HTTPException(status_code=502, detail="We could not complete that check. Try again shortly.") from error
    return {"status": result["safety_status"], "reason": result["safety_reason"], "response": result["response"]}
