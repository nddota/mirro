"""
Сравнение двух фотографий лица.

Подход намеренно лёгкий (без тяжёлых DL-моделей распознавания лиц, которые долго
собираются на Render/Fly и требуют много памяти):

  1. OpenCV Haar cascade находит лицо и вырезает/выравнивает область лица.
  2. Оба кропа приводятся к одному размеру и сравниваются через SSIM
     (structural similarity) — это даёт:
       - число похожести (0–100%)
       - карту отличий (где именно лицо изменилось), которую можно наложить
         тепловой картой поверх фото

Это не биометрическая идентификация "кто это", а именно отслеживание изменений
одного и того же лица день ко дню (отёчность, покраснения, асимметрия и т.п.) —
то, что нужно для личного трекинга.
"""

import cv2
import numpy as np
from skimage.metrics import structural_similarity as ssim

_face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")

FACE_SIZE = 320


class FaceNotFoundError(Exception):
    pass


def _detect_and_crop_face(img_bgr):
    gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
    faces = _face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(80, 80))
    if len(faces) == 0:
        return None
    # самое крупное найденное лицо в кадре
    x, y, w, h = max(faces, key=lambda f: f[2] * f[3])
    pad = int(0.15 * max(w, h))
    x0, y0 = max(0, x - pad), max(0, y - pad)
    x1, y1 = min(img_bgr.shape[1], x + w + pad), min(img_bgr.shape[0], y + h + pad)
    crop = img_bgr[y0:y1, x0:x1]
    crop = cv2.resize(crop, (FACE_SIZE, FACE_SIZE))
    return crop


def _decode(img_bytes):
    arr = np.frombuffer(img_bytes, np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("не удалось прочитать изображение")
    return img


def compare_faces(img_bytes_a: bytes, img_bytes_b: bytes) -> dict:
    img_a = _decode(img_bytes_a)
    img_b = _decode(img_bytes_b)

    face_a = _detect_and_crop_face(img_a)
    face_b = _detect_and_crop_face(img_b)
    if face_a is None or face_b is None:
        raise FaceNotFoundError("лицо не найдено на одном из фото")

    gray_a = cv2.cvtColor(face_a, cv2.COLOR_BGR2GRAY)
    gray_b = cv2.cvtColor(face_b, cv2.COLOR_BGR2GRAY)

    score, diff = ssim(gray_a, gray_b, full=True)
    diff_map = (diff * 255).astype("uint8")

    heatmap = cv2.applyColorMap(255 - diff_map, cv2.COLORMAP_JET)
    overlay = cv2.addWeighted(face_b, 0.55, heatmap, 0.45, 0)

    def encode(img):
        ok, buf = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 88])
        if not ok:
            raise ValueError("не удалось закодировать результат")
        return buf.tobytes()

    return {
        "similarity": round(float(score) * 100, 1),
        "face_a_jpg": encode(face_a),
        "face_b_jpg": encode(face_b),
        "diff_overlay_jpg": encode(overlay),
    }
