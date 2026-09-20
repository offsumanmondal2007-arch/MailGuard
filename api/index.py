import os
import sys
from pathlib import Path

# Add project root directory to Python path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Tell db.py and app that we are running in Vercel serverless environment
os.environ["VERCEL"] = "1"

from app import app
from mangum import Mangum

# Mangum wraps the FastAPI ASGI app for AWS Lambda / Vercel's serverless runtime.
# Without this, @vercel/python cannot invoke the ASGI app and returns 500.
handler = Mangum(app, lifespan="off")
