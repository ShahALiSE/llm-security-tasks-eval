from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND
from pathlib import Path
import shutil
import os
import magic  # python-magic

app = FastAPI()

UPLOAD_DIR = Path("uploaded_files")
UPLOAD_DIR.mkdir(exist_ok=True)

ALLOWED_MIME_TYPES = {"image/png", "image/jpeg", "application/pdf"}
MAX_FILE_SIZE_MB = 5


def get_file_mime_type(file_path: Path) -> str:
    """Detect the MIME type using libmagic."""
    return magic.from_file(str(file_path), mime=True)


def is_valid_file(file: UploadFile) -> bool:
    """Validate MIME type and file size."""
    content_type = file.content_type
    return content_type in ALLOWED_MIME_TYPES


@app.post("/upload/")
async def upload_file(file: UploadFile = File(...)):
    if not is_valid_file(file):
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid file type")

    file_path = UPLOAD_DIR / file.filename
    if ".." in file.filename or "/" in file.filename:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid file name")

    with file.file as source_file:
        with open(file_path, "wb") as dest_file:
            shutil.copyfileobj(source_file, dest_file)

    # Check actual MIME type after saving
    actual_mime = get_file_mime_type(file_path)
    if actual_mime not in ALLOWED_MIME_TYPES:
        file_path.unlink(missing_ok=True)
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="File content does not match allowed types")

    if file_path.stat().st_size > MAX_FILE_SIZE_MB * 1024 * 1024:
        file_path.unlink(missing_ok=True)
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="File too large")

    return {"filename": file.filename}


@app.get("/download/{filename}")
async def download_file(filename: str):
    file_path = UPLOAD_DIR / filename
    if ".." in filename or "/" in filename:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid file name")

    if not file_path.exists():
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="File not found")

    return FileResponse(path=file_path, filename=filename)
