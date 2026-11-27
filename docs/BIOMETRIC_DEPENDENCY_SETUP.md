# CRIME404 Face Recognition Dependency Setup

Face enrollment and verification are fail-closed. If `face-recognition`, `dlib`, or `numpy` cannot be imported, the server returns HTTP 503 and enrollment is not accepted. There is no descriptor upload or fallback enrollment path.

Activate the same virtual environment used to run Flask, then install:

```bash
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements-biometric.txt
```

On Windows, `dlib` may require CMake and the Visual Studio C++ Build Tools. If installation fails, do not bypass the dependency check or submit a manually supplied face descriptor. Use a compatible Python environment and install the native dependency successfully before restarting the Flask server.

After installation, restart CRIME404 and check the Profile page. Face recognition should report as available only when the server can import both `face_recognition` and `numpy`. This demo performs 1:1 face-template matching and does not provide liveness detection.
