"""Minimal API entry point."""

from fastapi import FastAPI

app = FastAPI(title="Project Remediator")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "service": "project-remediator"}
