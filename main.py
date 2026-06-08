import os
from contextlib import contextmanager
from datetime import datetime

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

load_dotenv()

PORT = int(os.getenv("PORT", "5000"))
DATABASE_URL = os.getenv("DATABASE_URL", "file:./dev.db")


def get_database_url() -> str:
    url = DATABASE_URL
    if url.startswith("file:"):
        path = url.removeprefix("file:").lstrip("./")
        return f"sqlite:///./{path}"
    return url


engine = create_engine(
    get_database_url(),
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class Base(DeclarativeBase):
    pass


class Risk(Base):
    __tablename__ = "Risk"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False)
    createdAt: Mapped[datetime] = mapped_column(
        "createdAt",
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )


class Notification(Base):
    __tablename__ = "Notification"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    riskId: Mapped[int] = mapped_column(
        "riskId",
        Integer,
        ForeignKey("Risk.id", ondelete="RESTRICT", onupdate="CASCADE"),
        nullable=False,
    )
    message: Mapped[str] = mapped_column(String, nullable=False)
    viewed: Mapped[bool] = mapped_column(
        "viewed",
        Boolean,
        nullable=False,
        server_default=text("false"),
    )
    createdAt: Mapped[datetime] = mapped_column(
        "createdAt",
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )


@contextmanager
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def serialize_risk(risk: Risk) -> dict:
    return {
        "id": risk.id,
        "title": risk.title,
        "description": risk.description,
        "createdAt": risk.createdAt.isoformat().replace("+00:00", "Z"),
    }


def serialize_notification(notification: Notification) -> dict:
    return {
        "id": notification.id,
        "riskId": notification.riskId,
        "message": notification.message,
        "viewed": notification.viewed,
        "createdAt": notification.createdAt.isoformat().replace("+00:00", "Z"),
    }


@app.post("/risks")
async def create_risk(body: dict):
    try:
        title = body["title"]
        description = body["description"]

        with get_db() as db:
            risk = Risk(title=title, description=description)
            db.add(risk)
            db.flush()

            notification = Notification(
                message=f"New Risk Created: {risk.title}",
                riskId=risk.id,
                viewed=False,
            )
            db.add(notification)
            db.commit()
            db.refresh(risk)

            return {"success": True, "risk": serialize_risk(risk)}
    except Exception:
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Failed to create risk"},
        )


@app.get("/risks")
async def list_risks():
    with get_db() as db:
        risks = db.query(Risk).order_by(Risk.createdAt.desc()).all()
        return [serialize_risk(risk) for risk in risks]


@app.get("/notifications")
async def list_notifications():
    with get_db() as db:
        notifications = (
            db.query(Notification).order_by(Notification.createdAt.desc()).all()
        )
        return [serialize_notification(notification) for notification in notifications]


if __name__ == "__main__":
    import uvicorn

    port = PORT
    uvicorn.run(app, host="0.0.0.0", port=port)
