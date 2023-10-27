from fastapi import FastAPI
import uvicorn
from states import get_tracking_state, change_tracking_state
app = FastAPI()


@app.put("/track/state/{state}")
def handle_change_track_state(state: bool):
    change_tracking_state(state)


@app.get("/track/state")
def handle_get_track_state():
    return get_tracking_state()


uvicorn.run(app, host="0.0.0.0", port=8000)
