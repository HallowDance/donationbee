from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from . import i18n
from .api import public, webhooks
from .web import recipient
from .web import routes as web

app = FastAPI(title="Verified Payment Proofs", docs_url="/api/docs", redoc_url=None)
app.include_router(public.router)
app.include_router(webhooks.router)
app.include_router(web.router)
app.include_router(recipient.router)
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "web" / "static"), name="static")


@app.middleware("http")
async def language(request, call_next):
    asked = request.query_params.get("lang")
    lang = i18n.choose(
        asked, request.cookies.get(i18n.COOKIE), request.headers.get("accept-language")
    )
    token = i18n.current.set(lang)
    try:
        response = await call_next(request)
    finally:
        i18n.current.reset(token)
    if asked in i18n.LANGS and request.cookies.get(i18n.COOKIE) != asked:
        response.set_cookie(
            i18n.COOKIE,
            asked,
            max_age=365 * 86400,
            samesite="lax",
            httponly=True,
            secure=request.url.scheme == "https",
        )
    vary = response.headers.get("Vary")
    response.headers["Vary"] = (
        f"{vary}, Accept-Language, Cookie" if vary else "Accept-Language, Cookie"
    )
    return response


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
