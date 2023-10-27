has_tracker_stopped = True
is_tracked = True


def get_is_tracked():
    return is_tracked


def change_is_tracked_state(value: bool):
    global is_tracked
    is_tracked = value


def change_tracking_state(value: bool):
    global has_tracker_stopped
    has_tracker_stopped = value


def get_tracking_state():
    return has_tracker_stopped
