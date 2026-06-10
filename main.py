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

from data.regulatory_change_alerts_seed import REGULATORY_CHANGE_ALERTS_SEED
from schemas.requests import AnalyzePolicyImpactRequest, CreateRiskRequest, PolicyGapAnalysisRequest
from schemas.responses import (
    AnalyzePolicyImpactResponse,
    CreateRiskResponse,
    DismissNotificationResponse,
    ExtractObligationsResponse,
    NotificationResponse,
    Obligation,
    PolicyGapAnalysisResponse,
    PolicyImpact,
    RegulatoryChangeAlertResponse,
    RiskResponse,
    SectionGapAnalysis,
)
from services.policy_analyzer import PolicyAnalyzer
from services.policy_gap_analyzer import PolicyGapAnalyzer
from services.obligation_extractor import ObligationExtractor

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
            if not conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name='Risk'")
            ).fetchone():
                logger.info("Risk table not found, skipping schema migration")
                return

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
                    text('ALTER TABLE "Risk" ADD COLUMN category TEXT NOT NULL DEFAULT \'\'')
                )

            columns = {
                row[1]
                for row in conn.execute(text("PRAGMA table_info(Risk)")).fetchall()
            }

            if "level" not in columns:
                logger.info("Migrating: Adding 'level' column")
                conn.execute(
                    text('ALTER TABLE "Risk" ADD COLUMN level TEXT NOT NULL DEFAULT \'\'')
                )

            if "type" not in columns:
                logger.info("Migrating: Adding 'type' column")
                conn.execute(
                    text('ALTER TABLE "Risk" ADD COLUMN type TEXT NOT NULL DEFAULT \'\'')
                )

            if "areasOfImpact" not in columns:
                logger.info("Migrating: Adding 'areasOfImpact' column")
                conn.execute(
                    text(
                        'ALTER TABLE "Risk" ADD COLUMN "areasOfImpact" TEXT NOT NULL DEFAULT \'\''
                    )
                )

            if "ownerOrganization" not in columns:
                logger.info("Migrating: Adding 'ownerOrganization' column")
                conn.execute(
                    text(
                        'ALTER TABLE "Risk" ADD COLUMN "ownerOrganization" TEXT NOT NULL DEFAULT \'\''
                    )
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

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False)
    category: Mapped[str] = mapped_column(
        String,
        nullable=False,
        server_default=text("''"),
    )
    level: Mapped[str] = mapped_column(String, nullable=False, server_default=text("''"))
    riskType: Mapped[str] = mapped_column("type", String, nullable=False, server_default=text("''"))
    areasOfImpact: Mapped[str] = mapped_column(
        "areasOfImpact",
        String,
        nullable=False,
        server_default=text("''"),
    )
    ownerOrganization: Mapped[str] = mapped_column(
        "ownerOrganization",
        String,
        nullable=False,
        server_default=text("''"),
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
    riskId: Mapped[str] = mapped_column(
        "riskId",
        String,
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


class RegulatoryChangeAlert(Base):
    __tablename__ = "Regulatory Change Alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alertId: Mapped[str] = mapped_column("alertId", String, nullable=False, unique=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    nativeTitle: Mapped[str | None] = mapped_column("nativeTitle", String, nullable=True)
    category: Mapped[str | None] = mapped_column(String, nullable=True)
    webUrl: Mapped[str | None] = mapped_column("webUrl", String, nullable=True)
    status: Mapped[str | None] = mapped_column(String, nullable=True)
    regulatoryPublicationAndOntology: Mapped[str | None] = mapped_column(
        "regulatoryPublicationAndOntology", String, nullable=True
    )
    ontology: Mapped[str | None] = mapped_column(String, nullable=True)
    nativeContent: Mapped[str | None] = mapped_column("nativeContent", String, nullable=True)
    classificationJurisdiction: Mapped[str | None] = mapped_column(
        "classificationJurisdiction", String, nullable=True
    )
    classificationCategory: Mapped[str | None] = mapped_column(
        "classificationCategory", String, nullable=True
    )
    classificationApplicableJurisdictions: Mapped[str | None] = mapped_column(
        "classificationApplicableJurisdictions", String, nullable=True
    )
    classificationRegulatoryBodies: Mapped[str | None] = mapped_column(
        "classificationRegulatoryBodies", String, nullable=True
    )
    keyDatesPublicationDate: Mapped[str | None] = mapped_column(
        "keyDatesPublicationDate", String, nullable=True
    )
    keyDatesIssuanceDate: Mapped[str | None] = mapped_column(
        "keyDatesIssuanceDate", String, nullable=True
    )
    referenceIds: Mapped[str | None] = mapped_column("referenceIds", String, nullable=True)
    referencesLinkUrl: Mapped[str | None] = mapped_column("referencesLinkUrl", String, nullable=True)
    providedBy: Mapped[str | None] = mapped_column("providedBy", String, nullable=True)
    providedOn: Mapped[str | None] = mapped_column("providedOn", String, nullable=True)
    informationType: Mapped[str | None] = mapped_column("informationType", String, nullable=True)
    impactedPolicies: Mapped[list] = mapped_column(
        "impactedPolicies",
        JSON,
        nullable=False,
        server_default=text("'[]'"),
    )


def generate_next_risk_id(db) -> str:
    max_num = 0
    for (risk_id,) in db.query(Risk.id).all():
        if isinstance(risk_id, str) and risk_id.startswith("RISK-"):
            try:
                max_num = max(max_num, int(risk_id.removeprefix("RISK-")))
            except ValueError:
                pass
    return f"RISK-{max_num + 1:03d}"


def migrate_risk_id_format():
    """Migrate Risk primary key from INTEGER to RISK-001 string format."""
    try:
        with engine.connect() as conn:
            if not conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name='Risk'")
            ).fetchone():
                Base.metadata.create_all(bind=engine, tables=[Risk.__table__, Notification.__table__])
                logger.info("Created Risk and Notification tables with string ids")
                return

            id_col = next(
                (
                    col
                    for col in conn.execute(text('PRAGMA table_info("Risk")')).fetchall()
                    if col[1] == "id"
                ),
                None,
            )
            if not id_col or id_col[2].upper() != "INTEGER":
                return

            logger.info("Migrating Risk id from INTEGER to RISK-XXX format")
            risks = conn.execute(
                text('SELECT id, name, description, category, "createdAt" FROM Risk ORDER BY id')
            ).fetchall()
            notifications = conn.execute(
                text('SELECT id, riskId, message, viewed, "createdAt" FROM Notification')
            ).fetchall()
            id_map = {row[0]: f"RISK-{row[0]:03d}" for row in risks}

            conn.execute(text("PRAGMA foreign_keys=OFF"))
            conn.execute(text('DROP TABLE IF EXISTS "Notification"'))
            conn.execute(text('DROP TABLE IF EXISTS "Risk"'))
            conn.commit()

        Base.metadata.create_all(bind=engine, tables=[Risk.__table__, Notification.__table__])

        with SessionLocal() as db:
            for old_id, name, description, category, created_at in risks:
                db.add(
                    Risk(
                        id=id_map[old_id],
                        name=name,
                        description=description,
                        category=category,
                        createdAt=created_at,
                    )
                )
            db.flush()
            for notif_id, risk_id, message, viewed, created_at in notifications:
                db.add(
                    Notification(
                        id=notif_id,
                        riskId=id_map[risk_id],
                        message=message,
                        viewed=viewed,
                        createdAt=created_at,
                    )
                )
            db.commit()
        logger.info("Risk id migration completed successfully")
    except Exception as e:
        logger.error(f"Risk id migration failed: {e}", exc_info=True)
        raise


migrate_risk_id_format()


def migrate_risk_list_fields_to_string():
    """Migrate category and areasOfImpact from JSON arrays to TEXT strings."""
    import json

    def to_string(value) -> str:
        if value is None:
            return ""
        if isinstance(value, list):
            return ", ".join(str(item) for item in value)
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, list):
                    return ", ".join(str(item) for item in parsed)
            except (json.JSONDecodeError, TypeError):
                pass
            return value
        return str(value)

    try:
        with engine.connect() as conn:
            if not conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name='Risk'")
            ).fetchone():
                return

            create_sql = conn.execute(
                text("SELECT sql FROM sqlite_master WHERE type='table' AND name='Risk'")
            ).scalar() or ""

            if "category JSON" not in create_sql and '"areasOfImpact" JSON' not in create_sql:
                return

            logger.info("Migrating Risk category and areasOfImpact from JSON to TEXT")
            risks = conn.execute(text('SELECT * FROM "Risk"')).mappings().all()
            notifications = conn.execute(text('SELECT * FROM "Notification"')).mappings().all()

            conn.execute(text("PRAGMA foreign_keys=OFF"))
            conn.execute(text('DROP TABLE IF EXISTS "Notification"'))
            conn.execute(text('DROP TABLE IF EXISTS "Risk"'))
            conn.commit()

        Base.metadata.create_all(bind=engine, tables=[Risk.__table__, Notification.__table__])

        with SessionLocal() as db:
            for row in risks:
                db.add(
                    Risk(
                        id=row["id"],
                        name=row["name"],
                        description=row.get("description") or "",
                        category=to_string(row.get("category")),
                        level=row.get("level") or "",
                        riskType=row.get("type") or "",
                        areasOfImpact=to_string(row.get("areasOfImpact")),
                        ownerOrganization=row.get("ownerOrganization") or "",
                        createdAt=row.get("createdAt"),
                    )
                )
            db.flush()
            for row in notifications:
                db.add(
                    Notification(
                        id=row["id"],
                        riskId=row["riskId"],
                        message=row["message"],
                        viewed=row["viewed"],
                        createdAt=row["createdAt"],
                    )
                )
            db.commit()
        logger.info("Risk JSON to TEXT migration completed successfully")
    except Exception as e:
        logger.error(f"Risk JSON to TEXT migration failed: {e}", exc_info=True)
        raise


migrate_risk_list_fields_to_string()


def init_regulatory_change_alerts():
    """Create Regulatory Change Alerts table and seed initial rows."""
    try:
        Base.metadata.create_all(bind=engine, tables=[RegulatoryChangeAlert.__table__])
        with SessionLocal() as db:
            for row in REGULATORY_CHANGE_ALERTS_SEED:
                existing = (
                    db.query(RegulatoryChangeAlert)
                    .filter(RegulatoryChangeAlert.alertId == row["alertId"])
                    .first()
                )
                if not existing:
                    db.add(RegulatoryChangeAlert(**row))
            db.commit()
        logger.info("Regulatory Change Alerts table initialized")
    except Exception as e:
        logger.error(f"Failed to initialize Regulatory Change Alerts: {e}", exc_info=True)
        raise


init_regulatory_change_alerts()


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


def serialize_notification(notification: Notification, risk_name: str) -> dict:
    return NotificationResponse(
        id=notification.id,
        riskId=notification.riskId,
        title=risk_name,
        viewed=notification.viewed,
        createdAt=notification.createdAt,
    ).model_dump(mode="json", by_alias=True)


@app.post("/risks", response_model=CreateRiskResponse)
async def create_risk(body: CreateRiskRequest):
    """Create a new risk and associated notification."""
    try:
        risk_name = (body.title or body.name).strip()
        category_value = (body.category or body.categories or "").strip()
        logger.info(f"Creating new risk: {risk_name}")
        with get_db() as db:
            risk = Risk(
                id=generate_next_risk_id(db),
                name=risk_name,
                description=body.description or "",
                category=category_value,
                level=body.level,
                riskType=body.type or "",
                areasOfImpact=body.areas_of_impact or "",
                ownerOrganization=body.owner_organization,
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


@app.get("/regulatory-change-alerts", response_model=list[RegulatoryChangeAlertResponse])
async def list_regulatory_change_alerts():
    """List all regulatory change alerts."""
    try:
        logger.debug("Fetching regulatory change alerts")
        with get_db() as db:
            alerts = db.query(RegulatoryChangeAlert).order_by(RegulatoryChangeAlert.id.asc()).all()
            logger.info(f"Retrieved {len(alerts)} regulatory change alerts")
            return [RegulatoryChangeAlertResponse.model_validate(alert) for alert in alerts]
    except SQLAlchemyError as e:
        logger.error(f"Database error fetching regulatory change alerts: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Failed to fetch regulatory change alerts"},
        )
    except Exception as e:
        logger.error(f"Unexpected error fetching regulatory change alerts: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Failed to fetch regulatory change alerts"},
        )


@app.get("/notifications", response_model=list[NotificationResponse])
async def list_notifications():
    """List all unviewed notifications."""
    try:
        logger.debug("Fetching unviewed notifications")
        with get_db() as db:
            rows = (
                db.query(Notification, Risk.name)
                .join(Risk, Notification.riskId == Risk.id)
                .filter(Notification.viewed == False)
                .order_by(Notification.createdAt.desc())
                .all()
            )
            logger.info(f"Retrieved {len(rows)} unviewed notifications")
            return [
                serialize_notification(notification, risk_name)
                for notification, risk_name in rows
            ]
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


def build_regulatory_content(alert: RegulatoryChangeAlert) -> str:
    """Concatenate all data fields of a regulatory change alert into one labelled text block."""
    field_labels = [
        ("Alert ID", alert.alertId),
        ("Title", alert.title),
        ("Native Title", alert.nativeTitle),
        ("Category", alert.category),
        ("Web URL", alert.webUrl),
        ("Status", alert.status),
        ("Regulatory Publication and Ontology", alert.regulatoryPublicationAndOntology),
        ("Ontology", alert.ontology),
        ("Native Content", alert.nativeContent),
        ("Classification - Jurisdiction", alert.classificationJurisdiction),
        ("Classification - Category", alert.classificationCategory),
        ("Classification - Applicable Jurisdictions", alert.classificationApplicableJurisdictions),
        ("Classification - Regulatory Bodies", alert.classificationRegulatoryBodies),
        ("Key Dates - Publication Date", alert.keyDatesPublicationDate),
        ("Key Dates - Issuance Date", alert.keyDatesIssuanceDate),
        ("Reference IDs", alert.referenceIds),
        ("References Link URL", alert.referencesLinkUrl),
        ("Provided By", alert.providedBy),
        ("Provided On", alert.providedOn),
        ("Information Type", alert.informationType),
    ]
    return "\n".join(
        f"{label}: {value}" for label, value in field_labels if value not in (None, "")
    )


@app.post(
    "/regulatory-change-alerts/{alert_id}/extract-obligations",
    response_model=ExtractObligationsResponse,
)
async def extract_obligations(alert_id: str):
    """
    Extract compliance obligations from a regulatory change alert's content using an LLM.
    Takes all data fields of the given regulatory change alert and returns extracted obligations.
    """
    try:
        logger.info(f"Starting obligation extraction for alert_id={alert_id}")
        with get_db() as db:
            alert = (
                db.query(RegulatoryChangeAlert)
                .filter(RegulatoryChangeAlert.alertId == alert_id)
                .first()
            )
            if not alert:
                logger.warning(f"Regulatory change alert not found: {alert_id}")
                return JSONResponse(
                    status_code=404,
                    content={"success": False, "message": "Regulatory change alert not found"},
                )

            regulatory_content = build_regulatory_content(alert)
            alert_title = alert.title

        extractor = ObligationExtractor()
        obligations = extractor.extract_obligations(regulatory_content)

        logger.info(
            f"Obligation extraction completed for alert_id={alert_id}, "
            f"found {len(obligations)} obligations"
        )
        return ExtractObligationsResponse(
            success=True,
            alert_id=alert_id,
            title=alert_title,
            obligations=[
                Obligation(
                    obligation_id=o.obligation_id,
                    obligation_text=o.obligation_text,
                    obligation_category=o.obligation_category,
                    priority=o.priority,
                    rationale=o.rationale,
                )
                for o in obligations
            ],
        )
    except ValueError as e:
        logger.error(f"Validation error in obligation extraction: {e}")
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": str(e)},
        )
    except SQLAlchemyError as e:
        logger.error(f"Database error in obligation extraction: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Database error occurred"},
        )
    except Exception as e:
        logger.error(f"Unexpected error in obligation extraction: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": f"Failed to extract obligations: {str(e)}"},
        )


if __name__ == "__main__":
    logger.info(f"Starting uvicorn server on port {PORT}")
    uvicorn.run(app, host="0.0.0.0", port=PORT)
