"""Pydantic schemas for Abuse Report API."""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr


class AbuseReportCreate(BaseModel):
    """Schema for creating abuse report."""

    scan_id: Optional[int] = Field(None, description="ID of scan to report (optional)")
    url: str = Field(..., description="URL being reported", min_length=1)
    report_type: str = Field(
        "phishing",
        description="Type of report",
        pattern="^(phishing|malware|spam|copyright|other)$",
    )
    recipient_emails: List[EmailStr] = Field(
        ..., description="Abuse contact email addresses", min_length=1
    )
    cc_emails: Optional[List[EmailStr]] = Field(
        None, description="CC recipients (optional)"
    )
    attachments: Optional[List[str]] = Field(
        None, description="Paths to attachment files"
    )
    manual_submission: bool = Field(
        False, description="Whether this is a manual submission"
    )
    additional_notes: Optional[str] = Field(
        None, description="Additional information for the report"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": 123,
                "url": "https://fake-paypal.com",
                "report_type": "phishing",
                "recipient_emails": ["abuse@registrar.com"],
                "cc_emails": ["team@company.com"],
                "manual_submission": True,
                "additional_notes": "This site is impersonating PayPal login page",
            }
        }


class AbuseReportSubmit(BaseModel):
    """Schema for submitting abuse report."""

    use_template: bool = Field(
        True, description="Whether to use professional template"
    )
    custom_subject: Optional[str] = Field(
        None, description="Custom subject (if not using template)"
    )
    custom_body: Optional[str] = Field(
        None, description="Custom body (if not using template)"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "use_template": True,
            }
        }


class AbuseReportAcknowledge(BaseModel):
    """Schema for acknowledging abuse report."""

    response_text: Optional[str] = Field(
        None, description="Response from abuse contact"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "response_text": "Thank you for your report. We are investigating."
            }
        }


class AbuseReportResolve(BaseModel):
    """Schema for resolving abuse report."""

    response_text: Optional[str] = Field(
        None, description="Final response from abuse contact"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "response_text": "The malicious site has been taken down. Thank you."
            }
        }


class AbuseReportResponse(BaseModel):
    """Schema for abuse report response."""

    id: int
    scan_id: Optional[int]
    user_id: int
    url: str
    report_type: str
    recipient_email: List[str]
    subject: Optional[str]
    status: str
    submitted_at: Optional[datetime]
    acknowledged_at: Optional[datetime]
    resolved_at: Optional[datetime]
    icann_sla_deadline: Optional[datetime]
    icann_sla_status: Optional[str]
    response_received: bool
    response_text: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": 1,
                "scan_id": 123,
                "user_id": 10,
                "url": "https://fake-paypal.com",
                "report_type": "phishing",
                "recipient_email": ["abuse@registrar.com"],
                "subject": "[URGENT] Phishing Site Report - fake-paypal.com",
                "status": "submitted",
                "submitted_at": "2026-01-03T10:30:00",
                "acknowledged_at": None,
                "resolved_at": None,
                "icann_sla_deadline": "2026-01-05T10:30:00",
                "icann_sla_status": "compliant",
                "response_received": False,
                "response_text": None,
                "created_at": "2026-01-03T10:00:00",
                "updated_at": "2026-01-03T10:30:00",
            }
        }


class SLAStatisticsResponse(BaseModel):
    """Schema for SLA statistics response."""

    total_active_reports: int
    compliant: int
    approaching_deadline: int
    overdue: int
    compliance_rate: float
    avg_response_hours: float

    class Config:
        json_schema_extra = {
            "example": {
                "total_active_reports": 50,
                "compliant": 40,
                "approaching_deadline": 8,
                "overdue": 2,
                "compliance_rate": 96.0,
                "avg_response_hours": 18.5,
            }
        }
