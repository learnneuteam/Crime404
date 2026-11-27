"""Consent-based face verification adapter.

Supports:
1. `face_recognition` (dlib 128-d embedding) when installed.
2. OpenCV (`cv2` + `numpy`) multi-pass Haar-cascade face detection + shift-tolerant
   spatial block histogram & projection profile descriptor when `dlib` is unavailable.

Only encrypted numeric face templates are retained; submitted image bytes are
processed in memory and are never written to disk.
"""
from __future__ import annotations
import base64
import io


class FaceServiceUnavailable(RuntimeError):
    pass


def _has_dlib_face_recognition() -> bool:
    try:
        import face_recognition  # noqa: F401
        import numpy  # noqa: F401
        return True
    except Exception:
        return False


def _has_opencv() -> bool:
    try:
        import cv2  # noqa: F401
        import numpy  # noqa: F401
        return True
    except Exception:
        return False


def is_available() -> bool:
    return _has_dlib_face_recognition() or _has_opencv()


def _numpy():
    try:
        import numpy as np
        return np
    except Exception as exc:
        raise FaceServiceUnavailable("NumPy is missing. Install opencv-python and numpy.") from exc


def _decode_data_url(data_url: str) -> bytes:
    if not isinstance(data_url, str) or "," not in data_url:
        raise ValueError("A camera image is required")
    header, encoded = data_url.split(",", 1)
    if "image/" not in header.lower() or len(encoded) > 5_000_000:
        raise ValueError("Unsupported or oversized camera image")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise ValueError("Invalid camera image encoding") from exc
    if len(raw) > 3_500_000:
        raise ValueError("Camera image exceeds the size limit")
    return raw


def _opencv_face_encoding(raw: bytes):
    import cv2
    np = _numpy()
    arr = np.frombuffer(raw, dtype=np.uint8)
    bgr = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if bgr is None:
        raise ValueError("Could not decode camera image")
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    clahe_full = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8)).apply(gray)
    eq_gray = cv2.equalizeHist(gray)
    faces = []
    for xml_name in (
        "haarcascade_frontalface_default.xml",
        "haarcascade_frontalface_alt2.xml",
        "haarcascade_frontalface_alt.xml",
    ):
        cascade = cv2.CascadeClassifier(cv2.data.haarcascades + xml_name)
        if cascade.empty():
            continue
        for img_pass in (clahe_full, eq_gray, gray):
            found = cascade.detectMultiScale(img_pass, scaleFactor=1.05, minNeighbors=2, minSize=(24, 24))
            if len(found) > 0:
                faces = list(found)
                break
        if faces:
            break
    if len(faces) == 0:
        raise ValueError("No face detected; move slightly closer and look straight at the camera")
    if len(faces) > 1:
        faces.sort(key=lambda b: b[2] * b[3], reverse=True)
        largest_area = faces[0][2] * faces[0][3]
        second_area = faces[1][2] * faces[1][3]
        if second_area >= 0.4 * largest_area:
            raise ValueError("Multiple faces detected; ensure only one face is visible")
    x, y, w, h = faces[0]

    mx, my = max(1, int(w * 0.12)), max(1, int(h * 0.12))
    crop = gray[y + my:y + h - my, x + mx:x + w - mx]
    if crop.size == 0:
        crop = gray[y:y + h, x:x + w]

    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(4, 4))
    norm_crop = clahe.apply(crop)
    resized = cv2.resize(norm_crop, (32, 32), interpolation=cv2.INTER_AREA).astype(np.float32) / 255.0

    # Shift-tolerant spatial block statistics (4x4 grid -> 16 blocks x 6 features = 96-d)
    # + horizontal & vertical intensity profiles (32 + 32 = 64-d) => 160-d unit vector
    feats = []
    for r in range(4):
        for c in range(4):
            blk = resized[r * 8:(r + 1) * 8, c * 8:(c + 1) * 8]
            feats.append(float(np.mean(blk)))
            feats.append(float(np.std(blk)))
            hist, _ = np.histogram(blk, bins=4, range=(0.0, 1.0))
            feats.extend((hist.astype(np.float32) / 64.0).tolist())

    row_prof = np.mean(resized, axis=1)
    col_prof = np.mean(resized, axis=0)
    feats.extend(row_prof.tolist())
    feats.extend(col_prof.tolist())

    vec = np.asarray(feats, dtype=np.float32)
    vec = vec - float(np.mean(vec))
    norm = float(np.linalg.norm(vec))
    if norm < 1e-6:
        raise ValueError("Face image has insufficient contrast; try better lighting")
    return (vec / norm).astype(np.float32)


def image_to_encoding(data_url: str):
    np = _numpy()
    raw = _decode_data_url(data_url)

    if _has_dlib_face_recognition():
        import face_recognition
        image = face_recognition.load_image_file(io.BytesIO(raw))
        locations = face_recognition.face_locations(image, model="hog")
        if len(locations) != 1:
            raise ValueError("Please ensure exactly one face is visible")
        encodings = face_recognition.face_encodings(image, known_face_locations=locations, num_jitters=1)
        if len(encodings) != 1:
            raise ValueError("Could not create a face template; try again with better lighting")
        return np.asarray(encodings[0], dtype=np.float32)

    if _has_opencv():
        return _opencv_face_encoding(raw)

    raise FaceServiceUnavailable("Face verification is not installed. Install opencv-python and numpy.")


def enrollment_template(images: list[str]) -> bytes:
    np = _numpy()
    if not isinstance(images, list) or not 3 <= len(images) <= 8:
        raise ValueError("Capture between 3 and 8 consented face samples")
    vectors = [image_to_encoding(item) for item in images]
    mean = np.mean(np.stack(vectors), axis=0)
    if _has_dlib_face_recognition():
        distances = [float(np.linalg.norm(v - mean)) for v in vectors]
        if max(distances) > 0.55:
            raise ValueError("Face samples are inconsistent; please enrol again")
        return mean.astype(np.float32).tobytes()
    norm = float(np.linalg.norm(mean))
    if norm > 1e-6:
        mean = mean / norm
    distances = [float(1.0 - np.dot(v, mean)) for v in vectors]
    if max(distances) > 0.35:
        raise ValueError("Face samples are inconsistent; please hold steady and enrol again")
    return mean.astype(np.float32).tobytes()


def verify_template(image: str, template_bytes: bytes, tolerance: float = 0.48):
    np = _numpy()
    probe = image_to_encoding(image)
    stored = np.frombuffer(template_bytes, dtype=np.float32)
    if stored.shape != probe.shape:
        raise ValueError("Stored face template format changed; please re-enroll your face in My Profile.")
    if stored.shape == (128,):
        distance = float(np.linalg.norm(probe - stored))
        return distance <= tolerance, distance
    cosine_dist = float(1.0 - np.dot(probe, stored))
    return cosine_dist <= 0.30, cosine_dist
