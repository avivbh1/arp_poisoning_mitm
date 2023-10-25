from fastapi import FastAPI
import uvicorn
from main import change_track_state, get_track_state
app = FastAPI()


@app.put("/track/state/{state}")
def handle_change_track_state(state: bool):
    change_track_state(state)


@app.get("/track/state")
def handle_get_track_state():
    return get_track_state()


@app.get("/")
def hello(name: str):
    return f"Hello, This is a plain text response."


uvicorn.run(app, host="0.0.0.0", port=8000)
