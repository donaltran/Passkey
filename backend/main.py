from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.router import api_router
from app.db.init_db import init_db

app = FastAPI(
    title = "Passkeyd",
    description="All encryption/decryption happens client-side. The server never sees your passwords.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    init_db()

app.include_router(api_router, prefix="/api/v1")

@app.get("/")
def root():
    return {"message": "Passkeyd", "docs": "/docs"}

@app.get("/health")
def health_check():
    return {"message": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)