"""Collaboration endpoints - Case Assignments & Team Notes."""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db, get_current_user
from src.services.collaboration_service import CollaborationService
from src.models.user import User
from src.models.case_assignment import CaseAssignment
from src.models.note import Note


router = APIRouter(prefix="/collaboration", tags=["Collaboration"])


# ========== SCHEMAS ==========

class CaseAssignmentRequest(BaseModel):
    """Case assignment creation request."""
    scan_id: Optional[int] = Field(None, description="Scan ID to assign")
    abuse_report_id: Optional[int] = Field(None, description="Abuse report ID to assign")
    assigned_to_user_id: Optional[int] = Field(None, description="Analyst to assign (auto-assign if null)")
    priority: str = Field("medium", description="Priority: low, medium, high, critical")
    due_date: Optional[datetime] = Field(None, description="Optional deadline")
    notes: Optional[str] = Field(None, description="Assignment notes")


class CaseAssignmentResponse(BaseModel):
    """Case assignment response."""
    id: int
    scan_id: Optional[int]
    abuse_report_id: Optional[int]
    assigned_to_user_id: int
    assigned_by_user_id: int
    status: str
    priority: str
    due_date: Optional[str]
    assigned_at: str
    accepted_at: Optional[str]
    completed_at: Optional[str]
    notes: Optional[str]
    completion_summary: Optional[str]

    class Config:
        from_attributes = True

    @classmethod
    def from_assignment(cls, assignment: CaseAssignment) -> "CaseAssignmentResponse":
        """Create response from CaseAssignment model."""
        return cls(
            id=assignment.id,
            scan_id=assignment.scan_id,
            abuse_report_id=assignment.abuse_report_id,
            assigned_to_user_id=assignment.assigned_to_user_id,
            assigned_by_user_id=assignment.assigned_by_user_id,
            status=assignment.status,
            priority=assignment.priority,
            due_date=assignment.due_date.isoformat() if assignment.due_date else None,
            assigned_at=assignment.assigned_at.isoformat(),
            accepted_at=assignment.accepted_at.isoformat() if assignment.accepted_at else None,
            completed_at=assignment.completed_at.isoformat() if assignment.completed_at else None,
            notes=assignment.notes,
            completion_summary=assignment.completion_summary
        )


class CaseCompletionRequest(BaseModel):
    """Case completion request."""
    completion_summary: str = Field(..., min_length=10, description="Work summary")


class ReassignmentRequest(BaseModel):
    """Case reassignment request."""
    new_analyst_id: int = Field(..., description="New analyst user ID")
    reason: Optional[str] = Field(None, description="Reassignment reason")


class WorkloadStatsResponse(BaseModel):
    """Analyst workload statistics."""
    user_id: int
    total_active: int
    pending: int
    in_progress: int
    high_priority: int
    overdue: int


class NoteCreateRequest(BaseModel):
    """Note creation request."""
    scan_id: Optional[int] = Field(None, description="Scan ID")
    abuse_report_id: Optional[int] = Field(None, description="Abuse report ID")
    case_assignment_id: Optional[int] = Field(None, description="Case assignment ID")
    content: str = Field(..., min_length=1, description="Note content (markdown supported)")
    is_important: bool = Field(False, description="Flag as important")
    mentions: Optional[List[int]] = Field(None, description="User IDs to mention")
    attachments: Optional[List[str]] = Field(None, description="Attachment file paths")


class NoteUpdateRequest(BaseModel):
    """Note update request."""
    content: str = Field(..., min_length=1, description="Updated content")


class NoteResponse(BaseModel):
    """Note response."""
    id: int
    scan_id: Optional[int]
    abuse_report_id: Optional[int]
    case_assignment_id: Optional[int]
    author_user_id: int
    content: str
    is_important: bool
    mentions: List[int]
    attachments: List[str]
    created_at: str
    updated_at: Optional[str]
    is_archived: bool

    class Config:
        from_attributes = True

    @classmethod
    def from_note(cls, note: Note) -> "NoteResponse":
        """Create response from Note model."""
        return cls(
            id=note.id,
            scan_id=note.scan_id,
            abuse_report_id=note.abuse_report_id,
            case_assignment_id=note.case_assignment_id,
            author_user_id=note.author_user_id,
            content=note.content,
            is_important=note.is_important,
            mentions=note.mentions or [],
            attachments=note.attachments or [],
            created_at=note.created_at.isoformat(),
            updated_at=note.updated_at.isoformat() if note.updated_at else None,
            is_archived=note.is_archived
        )


# ========== CASE ASSIGNMENT ENDPOINTS ==========

@router.post("/assignments", response_model=CaseAssignmentResponse, status_code=status.HTTP_201_CREATED)
async def create_assignment(
    request: CaseAssignmentRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a case assignment.

    Assigns a scan or abuse report to an analyst for investigation.
    If no analyst specified, uses load balancing to auto-assign.

    Args:
        request: Assignment request
        current_user: Authenticated user (manager assigning)
        db: Database session

    Returns:
        Created case assignment

    Example:
        POST /api/v1/collaboration/assignments
        {
            "scan_id": 123,
            "assigned_to_user_id": 5,
            "priority": "high",
            "notes": "Suspected phishing campaign"
        }
    """
    service = CollaborationService(db)

    try:
        # Auto-assign if no analyst specified
        if request.assigned_to_user_id is None:
            assignment = await service.auto_assign_case(
                assigned_by_user_id=current_user.id,
                scan_id=request.scan_id,
                abuse_report_id=request.abuse_report_id,
                priority=request.priority,
                due_date=request.due_date,
                notes=request.notes
            )
        else:
            assignment = await service.assign_case(
                assigned_to_user_id=request.assigned_to_user_id,
                assigned_by_user_id=current_user.id,
                scan_id=request.scan_id,
                abuse_report_id=request.abuse_report_id,
                priority=request.priority,
                due_date=request.due_date,
                notes=request.notes
            )

        return CaseAssignmentResponse.from_assignment(assignment)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create assignment: {str(e)}"
        )


@router.post("/assignments/{assignment_id}/accept", response_model=CaseAssignmentResponse)
async def accept_assignment(
    assignment_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Accept a case assignment.

    Analyst accepts an assigned case and marks it as in_progress.

    Args:
        assignment_id: Case assignment ID
        current_user: Authenticated user (assigned analyst)
        db: Database session

    Returns:
        Updated case assignment

    Example:
        POST /api/v1/collaboration/assignments/123/accept
    """
    service = CollaborationService(db)

    try:
        assignment = await service.accept_assignment(
            assignment_id=assignment_id,
            user_id=current_user.id
        )
        return CaseAssignmentResponse.from_assignment(assignment)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to accept assignment: {str(e)}"
        )


@router.post("/assignments/{assignment_id}/complete", response_model=CaseAssignmentResponse)
async def complete_assignment(
    assignment_id: int,
    request: CaseCompletionRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Complete a case assignment.

    Analyst marks case as completed with summary.

    Args:
        assignment_id: Case assignment ID
        request: Completion request with summary
        current_user: Authenticated user (assigned analyst)
        db: Database session

    Returns:
        Completed case assignment

    Example:
        POST /api/v1/collaboration/assignments/123/complete
        {
            "completion_summary": "Confirmed phishing. Contacted hosting provider."
        }
    """
    service = CollaborationService(db)

    try:
        assignment = await service.complete_assignment(
            assignment_id=assignment_id,
            user_id=current_user.id,
            completion_summary=request.completion_summary
        )
        return CaseAssignmentResponse.from_assignment(assignment)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to complete assignment: {str(e)}"
        )


@router.post("/assignments/{assignment_id}/reassign", response_model=CaseAssignmentResponse)
async def reassign_case(
    assignment_id: int,
    request: ReassignmentRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Reassign case to different analyst.

    Manager reassigns case to different team member.

    Args:
        assignment_id: Case assignment ID
        request: Reassignment request
        current_user: Authenticated user (manager)
        db: Database session

    Returns:
        Reassigned case assignment

    Example:
        POST /api/v1/collaboration/assignments/123/reassign
        {
            "new_analyst_id": 7,
            "reason": "Original analyst on vacation"
        }
    """
    service = CollaborationService(db)

    try:
        assignment = await service.reassign_case(
            assignment_id=assignment_id,
            new_analyst_id=request.new_analyst_id,
            reassigned_by_user_id=current_user.id,
            reason=request.reason
        )
        return CaseAssignmentResponse.from_assignment(assignment)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reassign case: {str(e)}"
        )


@router.get("/assignments/my-cases", response_model=List[CaseAssignmentResponse])
async def get_my_assignments(
    status_filter: Optional[List[str]] = Query(None, description="Filter by status"),
    priority_filter: Optional[List[str]] = Query(None, description="Filter by priority"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get current user's case assignments.

    Args:
        status_filter: Optional status filter (pending, in_progress, completed)
        priority_filter: Optional priority filter (low, medium, high, critical)
        current_user: Authenticated user
        db: Database session

    Returns:
        List of case assignments

    Example:
        GET /api/v1/collaboration/assignments/my-cases?status_filter=pending&status_filter=in_progress
    """
    service = CollaborationService(db)

    try:
        assignments = await service.get_user_assignments(
            user_id=current_user.id,
            status_filter=status_filter,
            priority_filter=priority_filter
        )
        return [CaseAssignmentResponse.from_assignment(a) for a in assignments]

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve assignments: {str(e)}"
        )


@router.get("/assignments/overdue", response_model=List[CaseAssignmentResponse])
async def get_overdue_assignments(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get overdue case assignments for current user.

    Args:
        current_user: Authenticated user
        db: Database session

    Returns:
        List of overdue case assignments

    Example:
        GET /api/v1/collaboration/assignments/overdue
    """
    service = CollaborationService(db)

    try:
        assignments = await service.get_overdue_assignments(user_id=current_user.id)
        return [CaseAssignmentResponse.from_assignment(a) for a in assignments]

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve overdue assignments: {str(e)}"
        )


@router.get("/workload/stats", response_model=List[WorkloadStatsResponse])
async def get_workload_statistics(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get team workload statistics.

    Returns workload metrics for all analysts.

    Args:
        current_user: Authenticated user
        db: Database session

    Returns:
        Workload statistics per analyst

    Example:
        GET /api/v1/collaboration/workload/stats
        [
            {
                "user_id": 5,
                "total_active": 12,
                "pending": 3,
                "in_progress": 9,
                "high_priority": 4,
                "overdue": 1
            }
        ]
    """
    service = CollaborationService(db)

    try:
        stats = await service.get_workload_stats()
        return [WorkloadStatsResponse(**s) for s in stats]

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve workload stats: {str(e)}"
        )


# ========== NOTES ENDPOINTS ==========

@router.post("/notes", response_model=NoteResponse, status_code=status.HTTP_201_CREATED)
async def create_note(
    request: NoteCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a note/comment.

    Add notes to scans, abuse reports, or case assignments.
    Supports markdown, @mentions, and attachments.

    Args:
        request: Note creation request
        current_user: Authenticated user (note author)
        db: Database session

    Returns:
        Created note

    Example:
        POST /api/v1/collaboration/notes
        {
            "scan_id": 123,
            "content": "Found additional phishing indicators @user5",
            "is_important": true,
            "mentions": [5]
        }
    """
    service = CollaborationService(db)

    try:
        note = await service.create_note(
            author_user_id=current_user.id,
            content=request.content,
            scan_id=request.scan_id,
            abuse_report_id=request.abuse_report_id,
            case_assignment_id=request.case_assignment_id,
            is_important=request.is_important,
            mentions=request.mentions,
            attachments=request.attachments
        )
        return NoteResponse.from_note(note)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create note: {str(e)}"
        )


@router.put("/notes/{note_id}", response_model=NoteResponse)
async def update_note(
    note_id: int,
    request: NoteUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update a note's content.

    Only note author can update.

    Args:
        note_id: Note ID to update
        request: Update request with new content
        current_user: Authenticated user (must be author)
        db: Database session

    Returns:
        Updated note

    Example:
        PUT /api/v1/collaboration/notes/456
        {
            "content": "Updated analysis findings"
        }
    """
    service = CollaborationService(db)

    try:
        note = await service.update_note(
            note_id=note_id,
            author_user_id=current_user.id,
            content=request.content
        )
        return NoteResponse.from_note(note)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update note: {str(e)}"
        )


@router.delete("/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
async def archive_note(
    note_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Archive a note (soft delete).

    Only note author can archive.

    Args:
        note_id: Note ID to archive
        current_user: Authenticated user (must be author)
        db: Database session

    Example:
        DELETE /api/v1/collaboration/notes/456
    """
    service = CollaborationService(db)

    try:
        await service.archive_note(
            note_id=note_id,
            user_id=current_user.id
        )
        return None

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to archive note: {str(e)}"
        )


@router.get("/notes", response_model=List[NoteResponse])
async def get_notes(
    scan_id: Optional[int] = Query(None, description="Filter by scan ID"),
    abuse_report_id: Optional[int] = Query(None, description="Filter by abuse report ID"),
    case_assignment_id: Optional[int] = Query(None, description="Filter by case assignment ID"),
    include_archived: bool = Query(False, description="Include archived notes"),
    important_only: bool = Query(False, description="Only important notes"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get notes for an entity.

    Args:
        scan_id: Optional scan ID filter
        abuse_report_id: Optional abuse report ID filter
        case_assignment_id: Optional case assignment ID filter
        include_archived: Include archived notes
        important_only: Only important notes
        current_user: Authenticated user
        db: Database session

    Returns:
        List of notes

    Example:
        GET /api/v1/collaboration/notes?scan_id=123&important_only=true
    """
    service = CollaborationService(db)

    try:
        notes = await service.get_notes(
            scan_id=scan_id,
            abuse_report_id=abuse_report_id,
            case_assignment_id=case_assignment_id,
            include_archived=include_archived,
            important_only=important_only
        )
        return [NoteResponse.from_note(n) for n in notes]

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve notes: {str(e)}"
        )


@router.get("/notes/mentions", response_model=List[NoteResponse])
async def get_my_mentions(
    days: int = Query(7, ge=1, le=90, description="Number of days to look back"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get notes where current user was mentioned.

    Args:
        days: Number of days to look back (1-90)
        current_user: Authenticated user
        db: Database session

    Returns:
        List of notes with @mentions

    Example:
        GET /api/v1/collaboration/notes/mentions?days=7
    """
    service = CollaborationService(db)

    try:
        notes = await service.get_user_mentions(
            user_id=current_user.id,
            days=days
        )
        return [NoteResponse.from_note(n) for n in notes]

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve mentions: {str(e)}"
        )
