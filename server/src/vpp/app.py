from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from .api import public, webhooks
from .web import recipient
from .web import routes as web

app = FastAPI(title="Verified Payment Proofs", docs_url="/api/docs", redoc_url=None)
app.include_router(public.router)
app.include_router(webhooks.router)
app.include_router(web.router)
app.include_router(recipient.router)
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "web" / "static"), name="static")


@app.get("/", include_in_schema=False)
def index():
    return RedirectResponse("/api/docs")


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/docs"):  # Swagger UI loads from a CDN
        return response
    # Pages load nothing from Stripe (Checkout is a redirect), so CSP can stay strict.
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "form-action 'self' https://checkout.stripe.com; frame-ancestors 'none'",
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    return response
