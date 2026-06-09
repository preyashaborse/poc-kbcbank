import logging
import os
from contextlib import contextmanager
from datetime import datetime
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

from schemas.requests import AnalyzePolicyImpactRequest, CreateRiskRequest, PolicyGapAnalysisRequest
from schemas.responses import (
    AnalyzePolicyImpactResponse,
    CreateRiskResponse,
    DismissNotificationResponse,
    PolicyGapAnalysisResponse,
    PolicyImpact,
    RiskResponse,
    SectionGapAnalysis,
)
from services.policy_analyzer import PolicyAnalyzer
from services.policy_gap_analyzer import PolicyGapAnalyzer

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

PORT = int(os.getenv("PORT", "5000"))
DATABASE_URL = os.getenv("DATABASE_URL", "file:./dev.db")

logger.info(f"Starting application with PORT={PORT}, DATABASE_URL={DATABASE_URL}")


def get_database_url() -> str:
    url = DATABASE_URL
    if url.startswith("file:"):
        path = url.removeprefix("file:").lstrip("./")
        return f"sqlite:///./{path}"
    return url


try:
    engine = create_engine(
        get_database_url(),
        connect_args={"check_same_thread": False},
    )
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    logger.info(f"Database engine created successfully: {get_database_url()}")
except Exception as e:
    logger.error(f"Failed to create database engine: {e}", exc_info=True)
    raise


def migrate_risk_schema():
    """Migrate database schema for Risk table."""
    try:
        logger.info("Starting database schema migration")
        with engine.connect() as conn:
            columns = {
                row[1]
                for row in conn.execute(text("PRAGMA table_info(Risk)")).fetchall()
            }
            
            if "title" in columns and "name" not in columns:
                logger.info("Migrating: Renaming 'title' column to 'name'")
                conn.execute(text('ALTER TABLE "Risk" RENAME COLUMN title TO name'))
            
            columns = {
                row[1]
                for row in conn.execute(text("PRAGMA table_info(Risk)")).fetchall()
            }
            
            if "category" not in columns:
                logger.info("Migrating: Adding 'category' column")
                conn.execute(
                    text('ALTER TABLE "Risk" ADD COLUMN category JSON NOT NULL DEFAULT \'[]\'')
                )
            
            conn.commit()
            logger.info("Database schema migration completed successfully")
    except Exception as e:
        logger.error(f"Database migration failed: {e}", exc_info=True)
        raise


migrate_risk_schema()

app = FastAPI(title="KBC Risk & Policy Analysis API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming requests and responses."""
    logger.info(f"Request: {request.method} {request.url.path}")
    try:
        response = await call_next(request)
        logger.info(f"Response: {request.method} {request.url.path} - Status: {response.status_code}")
        return response
    except Exception as e:
        logger.error(f"Request failed: {request.method} {request.url.path} - Error: {e}", exc_info=True)
        raise


@app.on_event("startup")
async def startup_event():
    """Log application startup."""
    logger.info("Application startup complete")


@app.on_event("shutdown")
async def shutdown_event():
    """Log application shutdown."""
    logger.info("Application shutting down")


class Base(DeclarativeBase):
    pass


class Risk(Base):
    __tablename__ = "Risk"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False)
    category: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        server_default=text("'[]'"),
    )
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
    """Database session context manager with error handling."""
    db = SessionLocal()
    try:
        yield db
    except SQLAlchemyError as e:
        logger.error(f"Database error: {e}", exc_info=True)
        db.rollback()
        raise
    finally:
        db.close()


def serialize_notification(notification: Notification) -> dict:
    return {
        "id": notification.id,
        "riskId": notification.riskId,
        "message": notification.message,
        "viewed": notification.viewed,
        "createdAt": notification.createdAt.isoformat().replace("+00:00", "Z"),
    }


@app.post("/risks", response_model=CreateRiskResponse)
async def create_risk(body: CreateRiskRequest):
    """Create a new risk and associated notification."""
    try:
        logger.info(f"Creating new risk: {body.title}")
        with get_db() as db:
            risk = Risk(
                name=body.title,
                description=body.description,
                category=body.category,
            )
            db.add(risk)
            db.flush()

            notification = Notification(
                message=f"New Risk Created: {risk.name}",
                riskId=risk.id,
                viewed=False,
            )
            db.add(notification)
            db.commit()
            db.refresh(risk)

            logger.info(f"Risk created successfully with ID: {risk.id}")
            return CreateRiskResponse(success=True, risk=RiskResponse.model_validate(risk))
    except IntegrityError as e:
        logger.error(f"Database integrity error creating risk: {e}", exc_info=True)
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Risk creation failed due to data constraint"},
        )
    except SQLAlchemyError as e:
        logger.error(f"Database error creating risk: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Database error occurred"},
        )
    except Exception as e:
        logger.error(f"Unexpected error creating risk: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Failed to create risk"},
        )


@app.get("/risks", response_model=list[RiskResponse])
async def list_risks():
    """List all risks ordered by creation date."""
    try:
        logger.debug("Fetching all risks")
        with get_db() as db:
            risks = db.query(Risk).order_by(Risk.createdAt.desc()).all()
            logger.info(f"Retrieved {len(risks)} risks")
            return [RiskResponse.model_validate(risk) for risk in risks]
    except SQLAlchemyError as e:
        logger.error(f"Database error fetching risks: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Failed to fetch risks"},
        )
    except Exception as e:
        logger.error(f"Unexpected error fetching risks: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Failed to fetch risks"},
        )


@app.get("/notifications")
async def list_notifications():
    """List all unviewed notifications."""
    try:
        logger.debug("Fetching unviewed notifications")
        with get_db() as db:
            notifications = (
                db.query(Notification)
                .filter(Notification.viewed == False)
                .order_by(Notification.createdAt.desc())
                .all()
            )
            logger.info(f"Retrieved {len(notifications)} unviewed notifications")
            return [serialize_notification(notification) for notification in notifications]
    except SQLAlchemyError as e:
        logger.error(f"Database error fetching notifications: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Failed to fetch notifications"},
        )
    except Exception as e:
        logger.error(f"Unexpected error fetching notifications: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Failed to fetch notifications"},
        )


@app.put("/notifications/{id}/dismiss", response_model=DismissNotificationResponse)
async def dismiss_notification(id: int):
    """Mark a notification as viewed/dismissed."""
    try:
        logger.info(f"Dismissing notification ID: {id}")
        with get_db() as db:
            notification = db.query(Notification).filter(Notification.id == id).first()
            if not notification:
                logger.warning(f"Notification not found: {id}")
                return JSONResponse(
                    status_code=404,
                    content={"success": False, "message": "Notification not found"},
                )

            notification.viewed = True
            db.commit()

            logger.info(f"Notification {id} dismissed successfully")
            return DismissNotificationResponse(success=True)
    except SQLAlchemyError as e:
        logger.error(f"Database error dismissing notification {id}: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Database error occurred"},
        )
    except Exception as e:
        logger.error(f"Unexpected error dismissing notification {id}: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Failed to dismiss notification"},
        )


@app.post("/risks/analyze-policy-impact", response_model=AnalyzePolicyImpactResponse)
async def analyze_policy_impact(body: AnalyzePolicyImpactRequest):
    """
    Analyze which policies are most impacted by a given risk.
    Returns top 5 policies with impact scores and rationale.
    """
    try:
        logger.info(f"Starting policy impact analysis for risk_id={body.risk_id}")
        with get_db() as db:
            risk = db.query(Risk).filter(Risk.id == body.risk_id).first()
            if not risk:
                logger.warning(f"Risk not found: {body.risk_id}")
                return JSONResponse(
                    status_code=404,
                    content={"success": False, "message": "Risk not found"},
                )
        
        analyzer = PolicyAnalyzer()
        
        impact_analyses = analyzer.analyze_risk_impact(
            risk_id=body.risk_id,
            risk_title=body.risk_title,
            risk_description=body.risk_description,
            top_n=5
        )
        
        impacted_policies = [
            PolicyImpact(
                policy_name=analysis.policy_name,
                rationale=analysis.rationale,
                score=analysis.score
            )
            for analysis in impact_analyses
        ]
        
        logger.info(f"Policy impact analysis completed for risk_id={body.risk_id}, found {len(impacted_policies)} impacted policies")
        return AnalyzePolicyImpactResponse(
            success=True,
            risk_id=body.risk_id,
            risk_title=body.risk_title,
            impacted_policies=impacted_policies
        )
    except ValueError as e:
        logger.error(f"Validation error in policy impact analysis: {e}")
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": str(e)},
        )
    except SQLAlchemyError as e:
        logger.error(f"Database error in policy impact analysis: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Database error occurred"},
        )
    except Exception as e:
        logger.error(f"Unexpected error in policy impact analysis: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": f"Failed to analyze policy impact: {str(e)}"},
        )


@app.post("/policies/gap-analysis", response_model=PolicyGapAnalysisResponse)
async def analyze_policy_gaps(body: PolicyGapAnalysisRequest):
    """
    Perform section-level gap analysis for a specific policy against a risk.
    Returns detailed analysis of each section with coverage status and recommendations.
    """
    try:
        logger.info(f"Starting gap analysis for policy '{body.policy_name}' against risk_id={body.risk_id}")
        with get_db() as db:
            risk = db.query(Risk).filter(Risk.id == body.risk_id).first()
            if not risk:
                logger.warning(f"Risk not found: {body.risk_id}")
                return JSONResponse(
                    status_code=404,
                    content={"success": False, "message": "Risk not found"},
                )
        
        gap_analyzer = PolicyGapAnalyzer()
        
        result = gap_analyzer.analyze_policy_gaps(
            risk_id=body.risk_id,
            risk_title=body.risk_title,
            risk_description=body.risk_description,
            policy_name=body.policy_name
        )
        
        section_analyses = [
            SectionGapAnalysis(
                section_number=analysis.section_number,
                section_title=analysis.section_title,
                coverage_status=analysis.coverage_status,
                gap_analysis=analysis.gap_analysis,
                recommended_section=analysis.recommended_section if analysis.recommended_section else None
            )
            for analysis in result["section_analyses"]
        ]
        
        logger.info(f"Gap analysis completed for policy '{body.policy_name}', analyzed {result['summary']['total_sections']} sections")
        return PolicyGapAnalysisResponse(
            success=True,
            risk_id=body.risk_id,
            risk_title=body.risk_title,
            policy_name=body.policy_name,
            section_analyses=section_analyses,
            summary=result["summary"]
        )
    except ValueError as e:
        logger.error(f"Validation error in gap analysis: {e}")
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": str(e)},
        )
    except SQLAlchemyError as e:
        logger.error(f"Database error in gap analysis: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Database error occurred"},
        )
    except Exception as e:
        logger.error(f"Unexpected error in gap analysis: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": f"Failed to analyze policy gaps: {str(e)}"},
        )


if __name__ == "__main__":
    logger.info(f"Starting uvicorn server on port {PORT}")
    uvicorn.run(app, host="0.0.0.0", port=PORT)
