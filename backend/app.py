from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from web_routes import router as api_router

app = FastAPI()

# CORS settings for frontend-backend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change to your frontend domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")

@app.get("/health")
def health_check():
    return {"status": "ok"}