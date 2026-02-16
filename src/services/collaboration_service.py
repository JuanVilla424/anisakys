"""Team Collaboration Service - Case Management & Notes.

Manages case assignments, team collaboration, and analyst workload distribution.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from sqlalchemy import select, func, and_, or_, Integer
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.case_assignment import CaseAssignment
from src.models.note import Note
from src.models.scan import Scan
from src.models.abuse_report import AbuseReport
from src.models.user import User

logger = logging.getLogger(__name__)


class CollaborationService:
    """Service for team collaboration and case management.

    Features:
    - Case assignment with load balancing
    - Analyst workload tracking
    - Notes and comments with @mentions
    - Priority-based task distribution

    Example:
        ```python
        service = CollaborationService(db)
        assignment = await service.assign_case(
            scan_id=123,
            assigned_to_user_id=5,
            assigned_by_user_id=1,
            priority="high"
        )
        ```
    """

    def __init__(self, db: AsyncSession):
        """Initialize collaboration service.

        Args:
            db: Database session
        """
        self.db = db

    async def assign_case(
        self,
        assigned_to_user_id: int,
        assigned_by_user_id: int,
        scan_id: Optional[int] = None,
        abuse_report_id: Optional[int] = None,
        priority: str = "medium",
        due_date: Optional[datetime] = None,
        notes: Optional[str] = None
    ) -> CaseAssignment:
        """Assign a case to an analyst.

        Args:
            assigned_to_user_id: Analyst to assign to
            assigned_by_user_id: Manager assigning the case
            scan_id: Optional scan ID
            abuse_report_id: Optional abuse report ID
            priority: Case priority (low, medium, high, critical)
            due_date: Optional deadline
            notes: Assignment notes from manager

        Returns:
            Created CaseAssignment object

        Example:
            ```python
            assignment = await service.assign_case(
                scan_id=123,
                assigned_to_user_id=5,
                assigned_by_user_id=1,
                priority="high",
                notes="Suspected phishing campaign"
            )
            ```
        """
        # Validate that at least one entity is provided
        if not scan_id and not abuse_report_id:
            raise ValueError("Must provide either scan_id or abuse_report_id")

        # Validate priority
        valid_priorities = ['low', 'medium', 'high', 'critical']
        if priority not in valid_priorities:
            raise ValueError(f"Priority must be one of: {valid_priorities}")

        # Create assignment
        assignment = CaseAssignment(
            scan_id=scan_id,
            abuse_report_id=abuse_report_id,
            assigned_to_user_id=assigned_to_user_id,
            assigned_by_user_id=assigned_by_user_id,
            status="pending",
            priority=priority,
            due_date=due_date,
            assigned_at=datetime.utcnow(),
            assignment_notes=notes
        )

        self.db.add(assignment)
        await self.db.commit()
        await self.db.refresh(assignment)

        logger.info(
            f"Assigned case {assignment.id} to user {assigned_to_user_id} "
            f"(priority: {priority})"
        )

        return assignment

    async def auto_assign_case(
        self,
        assigned_by_user_id: int,
        scan_id: Optional[int] = None,
        abuse_report_id: Optional[int] = None,
        priority: str = "medium",
        due_date: Optional[datetime] = None,
        notes: Optional[str] = None
    ) -> CaseAssignment:
        """Auto-assign case using load balancing.

        Finds the analyst with the least active cases and assigns to them.

        Args:
            assigned_by_user_id: Manager assigning the case
            scan_id: Optional scan ID
            abuse_report_id: Optional abuse report ID
            priority: Case priority
            due_date: Optional deadline
            notes: Assignment notes

        Returns:
            Created CaseAssignment object
        """
        # Get analyst with least active cases
        analyst = await self.get_least_loaded_analyst()

        if not analyst:
            raise ValueError("No analysts available for assignment")

        return await self.assign_case(
            assigned_to_user_id=analyst.id,
            assigned_by_user_id=assigned_by_user_id,
            scan_id=scan_id,
            abuse_report_id=abuse_report_id,
            priority=priority,
            due_date=due_date,
            notes=notes
        )

    async def get_least_loaded_analyst(self) -> Optional[User]:
        """Get analyst with least active cases.

        Returns:
            User object of least loaded analyst or None
        """
        # Subquery: Count active cases per analyst
        active_cases_subquery = (
            select(
                CaseAssignment.assigned_to_user_id,
                func.count(CaseAssignment.id).label('case_count')
            )
            .where(
                CaseAssignment.status.in_(['pending', 'in_progress'])
            )
            .group_by(CaseAssignment.assigned_to_user_id)
            .subquery()
        )

        # Get all active users with their case counts
        stmt = (
            select(User, func.coalesce(active_cases_subquery.c.case_count, 0).label('case_count'))
            .outerjoin(
                active_cases_subquery,
                User.id == active_cases_subquery.c.assigned_to_user_id
            )
            .where(User.status == 'active')
            .order_by(func.coalesce(active_cases_subquery.c.case_count, 0))
            .limit(1)
        )

        result = await self.db.execute(stmt)
        row = result.first()

        return row[0] if row else None

    async def accept_assignment(
        self,
        assignment_id: int,
        user_id: int
    ) -> CaseAssignment:
        """Analyst accepts an assigned case.

        Args:
            assignment_id: Case assignment ID
            user_id: User accepting (must be assigned_to)

        Returns:
            Updated CaseAssignment object
        """
        stmt = select(CaseAssignment).where(CaseAssignment.id == assignment_id)
        result = await self.db.execute(stmt)
        assignment = result.scalar_one_or_none()

        if not assignment:
            raise ValueError(f"Assignment {assignment_id} not found")

        if assignment.assigned_to_user_id != user_id:
            raise ValueError("Only assigned analyst can accept this case")

        if assignment.status != 'pending':
            raise ValueError(f"Cannot accept case in status: {assignment.status}")

        assignment.status = 'in_progress'
        assignment.accepted_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(assignment)

        logger.info(f"User {user_id} accepted assignment {assignment_id}")

        return assignment

    async def complete_assignment(
        self,
        assignment_id: int,
        user_id: int,
        completion_summary: str
    ) -> CaseAssignment:
        """Mark case assignment as completed.

        Args:
            assignment_id: Case assignment ID
            user_id: User completing (must be assigned_to)
            completion_summary: Summary of work done

        Returns:
            Updated CaseAssignment object
        """
        stmt = select(CaseAssignment).where(CaseAssignment.id == assignment_id)
        result = await self.db.execute(stmt)
        assignment = result.scalar_one_or_none()

        if not assignment:
            raise ValueError(f"Assignment {assignment_id} not found")

        if assignment.assigned_to_user_id != user_id:
            raise ValueError("Only assigned analyst can complete this case")

        assignment.status = 'completed'
        assignment.completed_at = datetime.utcnow()
        assignment.completion_summary = completion_summary

        await self.db.commit()
        await self.db.refresh(assignment)

        logger.info(f"User {user_id} completed assignment {assignment_id}")

        return assignment

    async def reassign_case(
        self,
        assignment_id: int,
        new_analyst_id: int,
        reassigned_by_user_id: int,
        reason: Optional[str] = None
    ) -> CaseAssignment:
        """Reassign case to different analyst.

        Args:
            assignment_id: Case assignment ID
            new_analyst_id: New analyst user ID
            reassigned_by_user_id: Manager performing reassignment
            reason: Optional reason for reassignment

        Returns:
            Updated CaseAssignment object
        """
        stmt = select(CaseAssignment).where(CaseAssignment.id == assignment_id)
        result = await self.db.execute(stmt)
        assignment = result.scalar_one_or_none()

        if not assignment:
            raise ValueError(f"Assignment {assignment_id} not found")

        old_analyst_id = assignment.assigned_to_user_id

        assignment.assigned_to_user_id = new_analyst_id
        assignment.assigned_by_user_id = reassigned_by_user_id
        assignment.status = 'pending'  # Reset to pending
        assignment.assigned_at = datetime.utcnow()
        assignment.accepted_at = None  # Clear acceptance
        assignment.assignment_notes = f"{assignment.assignment_notes}\n\nReassigned from user {old_analyst_id}: {reason}" if reason else assignment.assignment_notes

        await self.db.commit()
        await self.db.refresh(assignment)

        logger.info(
            f"Reassigned case {assignment_id} from user {old_analyst_id} "
            f"to user {new_analyst_id}"
        )

        return assignment

    async def get_user_assignments(
        self,
        user_id: int,
        status_filter: Optional[List[str]] = None,
        priority_filter: Optional[List[str]] = None
    ) -> List[CaseAssignment]:
        """Get all assignments for a user.

        Args:
            user_id: User ID to get assignments for
            status_filter: Optional list of statuses to filter by
            priority_filter: Optional list of priorities to filter by

        Returns:
            List of CaseAssignment objects
        """
        stmt = select(CaseAssignment).where(
            CaseAssignment.assigned_to_user_id == user_id
        )

        if status_filter:
            stmt = stmt.where(CaseAssignment.status.in_(status_filter))

        if priority_filter:
            stmt = stmt.where(CaseAssignment.priority.in_(priority_filter))

        stmt = stmt.order_by(
            CaseAssignment.priority.desc(),
            CaseAssignment.assigned_at.desc()
        )

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_overdue_assignments(
        self,
        user_id: Optional[int] = None
    ) -> List[CaseAssignment]:
        """Get overdue case assignments.

        Args:
            user_id: Optional user ID to filter by

        Returns:
            List of overdue CaseAssignment objects
        """
        now = datetime.utcnow()

        stmt = select(CaseAssignment).where(
            CaseAssignment.due_date < now,
            CaseAssignment.status.in_(['pending', 'in_progress'])
        )

        if user_id:
            stmt = stmt.where(CaseAssignment.assigned_to_user_id == user_id)

        stmt = stmt.order_by(CaseAssignment.due_date)

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_workload_stats(self) -> List[Dict]:
        """Get analyst workload statistics.

        Returns:
            List of dictionaries with analyst workload info

        Example:
            ```python
            stats = await service.get_workload_stats()
            # [
            #     {
            #         'user_id': 5,
            #         'total_active': 12,
            #         'pending': 3,
            #         'in_progress': 9,
            #         'high_priority': 4,
            #         'overdue': 1
            #     },
            #     ...
            # ]
            ```
        """
        now = datetime.utcnow()

        # Get active assignments grouped by user
        stmt = select(
            CaseAssignment.assigned_to_user_id.label('user_id'),
            func.count(CaseAssignment.id).label('total_active'),
            func.sum(
                func.cast(CaseAssignment.status == 'pending', Integer)
            ).label('pending'),
            func.sum(
                func.cast(CaseAssignment.status == 'in_progress', Integer)
            ).label('in_progress'),
            func.sum(
                func.cast(CaseAssignment.priority.in_(['high', 'critical']), Integer)
            ).label('high_priority'),
            func.sum(
                func.cast(
                    and_(
                        CaseAssignment.due_date < now,
                        CaseAssignment.status.in_(['pending', 'in_progress'])
                    ),
                    Integer
                )
            ).label('overdue')
        ).where(
            CaseAssignment.status.in_(['pending', 'in_progress'])
        ).group_by(
            CaseAssignment.assigned_to_user_id
        )

        result = await self.db.execute(stmt)

        stats = []
        for row in result:
            stats.append({
                'user_id': row.user_id,
                'total_active': row.total_active or 0,
                'pending': row.pending or 0,
                'in_progress': row.in_progress or 0,
                'high_priority': row.high_priority or 0,
                'overdue': row.overdue or 0
            })

        return stats

    # ========== NOTES MANAGEMENT ==========

    async def create_note(
        self,
        author_user_id: int,
        content: str,
        scan_id: Optional[int] = None,
        abuse_report_id: Optional[int] = None,
        case_assignment_id: Optional[int] = None,
        is_important: bool = False,
        mentions: Optional[List[int]] = None,
        attachments: Optional[List[str]] = None
    ) -> Note:
        """Create a note/comment.

        Args:
            author_user_id: User creating the note
            content: Note content (markdown supported)
            scan_id: Optional scan ID
            abuse_report_id: Optional abuse report ID
            case_assignment_id: Optional case assignment ID
            is_important: Flag as important
            mentions: Optional list of user IDs mentioned (@user)
            attachments: Optional list of attachment file paths

        Returns:
            Created Note object

        Example:
            ```python
            note = await service.create_note(
                author_user_id=5,
                scan_id=123,
                content="Found additional phishing indicators in JavaScript",
                is_important=True,
                mentions=[1, 3]  # Mention users 1 and 3
            )
            ```
        """
        # Validate that at least one entity is provided
        if not any([scan_id, abuse_report_id, case_assignment_id]):
            raise ValueError(
                "Must provide at least one of: scan_id, abuse_report_id, case_assignment_id"
            )

        note = Note(
            scan_id=scan_id,
            abuse_report_id=abuse_report_id,
            case_assignment_id=case_assignment_id,
            author_user_id=author_user_id,
            content=content,
            is_important=is_important,
            mentions=mentions or [],
            attachments=attachments or [],
            created_at=datetime.utcnow(),
            is_archived=False
        )

        self.db.add(note)
        await self.db.commit()
        await self.db.refresh(note)

        logger.info(
            f"User {author_user_id} created note {note.id} "
            f"(important: {is_important}, mentions: {len(mentions or [])})"
        )

        return note

    async def update_note(
        self,
        note_id: int,
        author_user_id: int,
        content: str
    ) -> Note:
        """Update a note's content.

        Args:
            note_id: Note ID to update
            author_user_id: User updating (must be original author)
            content: New content

        Returns:
            Updated Note object
        """
        stmt = select(Note).where(Note.id == note_id)
        result = await self.db.execute(stmt)
        note = result.scalar_one_or_none()

        if not note:
            raise ValueError(f"Note {note_id} not found")

        if note.author_user_id != author_user_id:
            raise ValueError("Only note author can update this note")

        if note.is_archived:
            raise ValueError("Cannot update archived note")

        note.content = content
        note.updated_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(note)

        logger.info(f"User {author_user_id} updated note {note_id}")

        return note

    async def archive_note(
        self,
        note_id: int,
        user_id: int
    ) -> Note:
        """Archive a note (soft delete).

        Args:
            note_id: Note ID to archive
            user_id: User archiving (must be author)

        Returns:
            Archived Note object
        """
        stmt = select(Note).where(Note.id == note_id)
        result = await self.db.execute(stmt)
        note = result.scalar_one_or_none()

        if not note:
            raise ValueError(f"Note {note_id} not found")

        if note.author_user_id != user_id:
            raise ValueError("Only note author can archive this note")

        note.is_archived = True
        note.updated_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(note)

        logger.info(f"User {user_id} archived note {note_id}")

        return note

    async def get_notes(
        self,
        scan_id: Optional[int] = None,
        abuse_report_id: Optional[int] = None,
        case_assignment_id: Optional[int] = None,
        include_archived: bool = False,
        important_only: bool = False
    ) -> List[Note]:
        """Get notes for an entity.

        Args:
            scan_id: Optional scan ID
            abuse_report_id: Optional abuse report ID
            case_assignment_id: Optional case assignment ID
            include_archived: Include archived notes
            important_only: Only important notes

        Returns:
            List of Note objects ordered by created_at desc
        """
        stmt = select(Note)

        # Filter by entity
        conditions = []
        if scan_id:
            conditions.append(Note.scan_id == scan_id)
        if abuse_report_id:
            conditions.append(Note.abuse_report_id == abuse_report_id)
        if case_assignment_id:
            conditions.append(Note.case_assignment_id == case_assignment_id)

        if conditions:
            stmt = stmt.where(or_(*conditions))

        # Filter archived
        if not include_archived:
            stmt = stmt.where(Note.is_archived == False)

        # Filter important
        if important_only:
            stmt = stmt.where(Note.is_important == True)

        stmt = stmt.order_by(Note.created_at.desc())

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_user_mentions(
        self,
        user_id: int,
        days: int = 7
    ) -> List[Note]:
        """Get notes where user was mentioned.

        Args:
            user_id: User ID to find mentions for
            days: Number of days to look back

        Returns:
            List of Note objects where user was mentioned
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days)

        # PostgreSQL-specific: Check if user_id is in mentions array
        stmt = select(Note).where(
            Note.mentions.contains([user_id]),
            Note.created_at >= cutoff_date,
            Note.is_archived == False
        ).order_by(Note.created_at.desc())

        result = await self.db.execute(stmt)
        return list(result.scalars().all())
