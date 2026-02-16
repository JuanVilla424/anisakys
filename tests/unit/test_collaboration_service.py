"""Unit tests for Team Collaboration Service (UC-060, UC-061).

Tests:
- Case assignment creation
- Auto-assignment with load balancing
- Assignment acceptance
- Assignment completion
- Case reassignment
- Workload statistics
- Note creation and management
- Note @mentions
- Note archiving
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timedelta

from src.services.collaboration_service import CollaborationService
from src.models.case_assignment import CaseAssignment
from src.models.note import Note
from src.models.user import User


class TestCaseAssignment:
    """Test case assignment creation."""

    @pytest.mark.asyncio
    async def test_assign_case_to_analyst(self):
        """Should assign case to specified analyst."""
        db = AsyncMock()
        service = CollaborationService(db)

        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        assignment = await service.assign_case(
            assigned_to_user_id=5,
            assigned_by_user_id=1,
            scan_id=123,
            priority="high",
            notes="Suspected phishing"
        )

        assert db.add.called
        assert db.commit.called

    @pytest.mark.asyncio
    async def test_assign_case_invalid_priority(self):
        """Should raise ValueError for invalid priority."""
        db = AsyncMock()
        service = CollaborationService(db)

        with pytest.raises(ValueError, match="Priority must be one of"):
            await service.assign_case(
                assigned_to_user_id=5,
                assigned_by_user_id=1,
                scan_id=123,
                priority="ultra-high"  # Invalid
            )

    @pytest.mark.asyncio
    async def test_assign_case_no_entity(self):
        """Should raise ValueError if no scan_id or abuse_report_id provided."""
        db = AsyncMock()
        service = CollaborationService(db)

        with pytest.raises(ValueError, match="Must provide either"):
            await service.assign_case(
                assigned_to_user_id=5,
                assigned_by_user_id=1,
                priority="medium"
            )

    @pytest.mark.asyncio
    async def test_assign_case_with_due_date(self):
        """Should assign case with due date."""
        db = AsyncMock()
        service = CollaborationService(db)

        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        due_date = datetime.utcnow() + timedelta(days=3)

        assignment = await service.assign_case(
            assigned_to_user_id=5,
            assigned_by_user_id=1,
            scan_id=123,
            priority="critical",
            due_date=due_date,
            notes="Urgent investigation needed"
        )

        assert db.add.called
        assert db.commit.called


class TestAutoAssignment:
    """Test auto-assignment with load balancing."""

    @pytest.mark.asyncio
    async def test_get_least_loaded_analyst(self):
        """Should identify analyst with least active cases."""
        db = AsyncMock()
        service = CollaborationService(db)

        # Mock database response - user with least cases
        mock_user = User(id=5, email="analyst@example.com", password_hash="hash", tier="professional", status="active")

        mock_result = MagicMock()
        mock_result.first.return_value = (mock_user, 2)  # User with 2 active cases
        db.execute.return_value = mock_result

        analyst = await service.get_least_loaded_analyst()

        assert analyst is not None
        assert analyst.id == 5

    @pytest.mark.asyncio
    async def test_get_least_loaded_analyst_none_available(self):
        """Should return None if no analysts available."""
        db = AsyncMock()
        service = CollaborationService(db)

        # Mock database response - no users
        mock_result = MagicMock()
        mock_result.first.return_value = None
        db.execute.return_value = mock_result

        analyst = await service.get_least_loaded_analyst()

        assert analyst is None

    @pytest.mark.asyncio
    async def test_auto_assign_case(self):
        """Should auto-assign case to least loaded analyst."""
        db = AsyncMock()
        service = CollaborationService(db)

        # Mock get_least_loaded_analyst
        mock_user = User(id=7, email="analyst@example.com", password_hash="hash", tier="professional", status="active")

        mock_result = MagicMock()
        mock_result.first.return_value = (mock_user, 0)
        db.execute.return_value = mock_result

        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        assignment = await service.auto_assign_case(
            assigned_by_user_id=1,
            scan_id=123,
            priority="medium"
        )

        assert db.add.called
        assert db.commit.called

    @pytest.mark.asyncio
    async def test_auto_assign_case_no_analysts(self):
        """Should raise ValueError if no analysts available."""
        db = AsyncMock()
        service = CollaborationService(db)

        # Mock no analysts available
        mock_result = MagicMock()
        mock_result.first.return_value = None
        db.execute.return_value = mock_result

        with pytest.raises(ValueError, match="No analysts available"):
            await service.auto_assign_case(
                assigned_by_user_id=1,
                scan_id=123,
                priority="medium"
            )


class TestAssignmentAcceptance:
    """Test assignment acceptance by analyst."""

    @pytest.mark.asyncio
    async def test_accept_assignment_success(self):
        """Analyst should successfully accept pending assignment."""
        db = AsyncMock()
        service = CollaborationService(db)

        # Mock assignment lookup
        assignment = CaseAssignment(
            id=1,
            scan_id=123,
            assigned_to_user_id=5,
            assigned_by_user_id=1,
            status="pending",
            priority="medium",
            assigned_at=datetime.utcnow()
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = assignment
        db.execute.return_value = mock_result

        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        updated = await service.accept_assignment(assignment_id=1, user_id=5)

        assert updated.status == 'in_progress'
        assert updated.accepted_at is not None
        assert db.commit.called

    @pytest.mark.asyncio
    async def test_accept_assignment_not_found(self):
        """Should raise ValueError if assignment not found."""
        db = AsyncMock()
        service = CollaborationService(db)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute.return_value = mock_result

        with pytest.raises(ValueError, match="not found"):
            await service.accept_assignment(assignment_id=999, user_id=5)

    @pytest.mark.asyncio
    async def test_accept_assignment_wrong_user(self):
        """Should raise ValueError if wrong user tries to accept."""
        db = AsyncMock()
        service = CollaborationService(db)

        assignment = CaseAssignment(
            id=1,
            scan_id=123,
            assigned_to_user_id=5,
            assigned_by_user_id=1,
            status="pending",
            priority="medium",
            assigned_at=datetime.utcnow()
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = assignment
        db.execute.return_value = mock_result

        with pytest.raises(ValueError, match="Only assigned analyst"):
            await service.accept_assignment(assignment_id=1, user_id=7)  # Wrong user

    @pytest.mark.asyncio
    async def test_accept_assignment_wrong_status(self):
        """Should raise ValueError if assignment not in pending status."""
        db = AsyncMock()
        service = CollaborationService(db)

        assignment = CaseAssignment(
            id=1,
            scan_id=123,
            assigned_to_user_id=5,
            assigned_by_user_id=1,
            status="completed",  # Already completed
            priority="medium",
            assigned_at=datetime.utcnow()
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = assignment
        db.execute.return_value = mock_result

        with pytest.raises(ValueError, match="Cannot accept case in status"):
            await service.accept_assignment(assignment_id=1, user_id=5)


class TestAssignmentCompletion:
    """Test assignment completion."""

    @pytest.mark.asyncio
    async def test_complete_assignment_success(self):
        """Analyst should successfully complete assignment."""
        db = AsyncMock()
        service = CollaborationService(db)

        assignment = CaseAssignment(
            id=1,
            scan_id=123,
            assigned_to_user_id=5,
            assigned_by_user_id=1,
            status="in_progress",
            priority="medium",
            assigned_at=datetime.utcnow()
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = assignment
        db.execute.return_value = mock_result

        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        updated = await service.complete_assignment(
            assignment_id=1,
            user_id=5,
            completion_summary="Confirmed phishing. Contacted hosting provider."
        )

        assert updated.status == 'completed'
        assert updated.completed_at is not None
        assert updated.completion_summary == "Confirmed phishing. Contacted hosting provider."
        assert db.commit.called


class TestCaseReassignment:
    """Test case reassignment."""

    @pytest.mark.asyncio
    async def test_reassign_case_success(self):
        """Should successfully reassign case to different analyst."""
        db = AsyncMock()
        service = CollaborationService(db)

        assignment = CaseAssignment(
            id=1,
            scan_id=123,
            assigned_to_user_id=5,
            assigned_by_user_id=1,
            status="in_progress",
            priority="high",
            assigned_at=datetime.utcnow(),
            assignment_notes="Original assignment"
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = assignment
        db.execute.return_value = mock_result

        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        updated = await service.reassign_case(
            assignment_id=1,
            new_analyst_id=7,
            reassigned_by_user_id=1,
            reason="Original analyst on vacation"
        )

        assert updated.assigned_to_user_id == 7
        assert updated.status == 'pending'
        assert updated.accepted_at is None
        assert "Original analyst on vacation" in updated.assignment_notes
        assert db.commit.called


class TestUserAssignments:
    """Test user assignment retrieval."""

    @pytest.mark.asyncio
    async def test_get_user_assignments(self):
        """Should retrieve user's assignments."""
        db = AsyncMock()
        service = CollaborationService(db)

        mock_assignments = [
            CaseAssignment(
                id=1,
                scan_id=123,
                assigned_to_user_id=5,
                assigned_by_user_id=1,
                status="pending",
                priority="high",
                assigned_at=datetime.utcnow()
            )
        ]

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_assignments
        db.execute.return_value = mock_result

        assignments = await service.get_user_assignments(user_id=5)

        assert len(assignments) == 1
        assert assignments[0].assigned_to_user_id == 5

    @pytest.mark.asyncio
    async def test_get_user_assignments_with_filters(self):
        """Should filter assignments by status and priority."""
        db = AsyncMock()
        service = CollaborationService(db)

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        db.execute.return_value = mock_result

        assignments = await service.get_user_assignments(
            user_id=5,
            status_filter=['pending', 'in_progress'],
            priority_filter=['high', 'critical']
        )

        assert isinstance(assignments, list)


class TestOverdueAssignments:
    """Test overdue assignment retrieval."""

    @pytest.mark.asyncio
    async def test_get_overdue_assignments(self):
        """Should retrieve overdue assignments."""
        db = AsyncMock()
        service = CollaborationService(db)

        overdue_assignment = CaseAssignment(
            id=1,
            scan_id=123,
            assigned_to_user_id=5,
            assigned_by_user_id=1,
            status="in_progress",
            priority="high",
            due_date=datetime.utcnow() - timedelta(days=2),  # Overdue
            assigned_at=datetime.utcnow() - timedelta(days=5)
        )

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [overdue_assignment]
        db.execute.return_value = mock_result

        assignments = await service.get_overdue_assignments(user_id=5)

        assert len(assignments) == 1
        assert assignments[0].due_date < datetime.utcnow()


class TestWorkloadStatistics:
    """Test workload statistics."""

    @pytest.mark.asyncio
    async def test_get_workload_stats(self):
        """Should retrieve workload statistics for all analysts."""
        db = AsyncMock()
        service = CollaborationService(db)

        mock_stats = [
            MagicMock(
                user_id=5,
                total_active=12,
                pending=3,
                in_progress=9,
                high_priority=4,
                overdue=1
            )
        ]

        mock_result = MagicMock()
        mock_result.__iter__ = lambda self: iter(mock_stats)
        db.execute.return_value = mock_result

        stats = await service.get_workload_stats()

        assert len(stats) == 1
        assert stats[0]['user_id'] == 5
        assert stats[0]['total_active'] == 12
        assert stats[0]['pending'] == 3


class TestNoteCreation:
    """Test note creation."""

    @pytest.mark.asyncio
    async def test_create_note_success(self):
        """Should create note successfully."""
        db = AsyncMock()
        service = CollaborationService(db)

        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        note = await service.create_note(
            author_user_id=5,
            content="Found additional phishing indicators",
            scan_id=123,
            is_important=True,
            mentions=[1, 3]
        )

        assert db.add.called
        assert db.commit.called

    @pytest.mark.asyncio
    async def test_create_note_no_entity(self):
        """Should raise ValueError if no entity specified."""
        db = AsyncMock()
        service = CollaborationService(db)

        with pytest.raises(ValueError, match="Must provide at least one of"):
            await service.create_note(
                author_user_id=5,
                content="Test note"
            )

    @pytest.mark.asyncio
    async def test_create_note_with_mentions(self):
        """Should create note with @mentions."""
        db = AsyncMock()
        service = CollaborationService(db)

        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        note = await service.create_note(
            author_user_id=5,
            content="@user1 @user3 please review",
            scan_id=123,
            mentions=[1, 3]
        )

        assert db.add.called


class TestNoteUpdate:
    """Test note updating."""

    @pytest.mark.asyncio
    async def test_update_note_success(self):
        """Should update note content."""
        db = AsyncMock()
        service = CollaborationService(db)

        note = Note(
            id=1,
            author_user_id=5,
            content="Original content",
            scan_id=123,
            is_important=False,
            mentions=[],
            attachments=[],
            created_at=datetime.utcnow(),
            is_archived=False
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = note
        db.execute.return_value = mock_result

        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        updated = await service.update_note(
            note_id=1,
            author_user_id=5,
            content="Updated content"
        )

        assert updated.content == "Updated content"
        assert updated.updated_at is not None
        assert db.commit.called

    @pytest.mark.asyncio
    async def test_update_note_wrong_author(self):
        """Should raise ValueError if wrong user tries to update."""
        db = AsyncMock()
        service = CollaborationService(db)

        note = Note(
            id=1,
            author_user_id=5,
            content="Original content",
            scan_id=123,
            is_important=False,
            mentions=[],
            attachments=[],
            created_at=datetime.utcnow(),
            is_archived=False
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = note
        db.execute.return_value = mock_result

        with pytest.raises(ValueError, match="Only note author"):
            await service.update_note(note_id=1, author_user_id=7, content="Hacked")

    @pytest.mark.asyncio
    async def test_update_note_archived(self):
        """Should raise ValueError if note is archived."""
        db = AsyncMock()
        service = CollaborationService(db)

        note = Note(
            id=1,
            author_user_id=5,
            content="Archived note",
            scan_id=123,
            is_important=False,
            mentions=[],
            attachments=[],
            created_at=datetime.utcnow(),
            is_archived=True
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = note
        db.execute.return_value = mock_result

        with pytest.raises(ValueError, match="Cannot update archived note"):
            await service.update_note(note_id=1, author_user_id=5, content="Update")


class TestNoteArchiving:
    """Test note archiving (soft delete)."""

    @pytest.mark.asyncio
    async def test_archive_note_success(self):
        """Should archive note successfully."""
        db = AsyncMock()
        service = CollaborationService(db)

        note = Note(
            id=1,
            author_user_id=5,
            content="To be archived",
            scan_id=123,
            is_important=False,
            mentions=[],
            attachments=[],
            created_at=datetime.utcnow(),
            is_archived=False
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = note
        db.execute.return_value = mock_result

        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        archived = await service.archive_note(note_id=1, user_id=5)

        assert archived.is_archived is True
        assert archived.updated_at is not None
        assert db.commit.called


class TestNoteRetrieval:
    """Test note retrieval."""

    @pytest.mark.asyncio
    async def test_get_notes_for_scan(self):
        """Should retrieve notes for scan."""
        db = AsyncMock()
        service = CollaborationService(db)

        mock_notes = [
            Note(
                id=1,
                author_user_id=5,
                content="Analysis note",
                scan_id=123,
                is_important=False,
                mentions=[],
                attachments=[],
                created_at=datetime.utcnow(),
                is_archived=False
            )
        ]

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_notes
        db.execute.return_value = mock_result

        notes = await service.get_notes(scan_id=123)

        assert len(notes) == 1
        assert notes[0].scan_id == 123


class TestUserMentions:
    """Test user @mention retrieval."""

    @pytest.mark.asyncio
    async def test_get_user_mentions(self):
        """Should retrieve notes where user was mentioned."""
        db = AsyncMock()
        service = CollaborationService(db)

        mock_notes = [
            Note(
                id=1,
                author_user_id=3,
                content="@user5 please review",
                scan_id=123,
                is_important=True,
                mentions=[5],
                attachments=[],
                created_at=datetime.utcnow(),
                is_archived=False
            )
        ]

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_notes
        db.execute.return_value = mock_result

        notes = await service.get_user_mentions(user_id=5, days=7)

        assert len(notes) == 1
        assert 5 in notes[0].mentions
