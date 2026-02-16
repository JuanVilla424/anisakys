"""Sprint 4: Advanced Features - Typosquatting, CT Monitoring, Collaboration

Revision ID: 003_sprint4
Revises: 002_add_whois_data
Create Date: 2026-01-03

Tables Added:
- domain_variants: Typosquatting detection
- ct_certificates: Certificate Transparency monitoring
- case_assignments: Team collaboration
- notes: Notes & comments
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '003_sprint4'
down_revision = '002_add_whois_data'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add Sprint 4 tables for advanced features."""

    # ========== 1. Domain Variants Table (Typosquatting Detection) ==========
    op.create_table(
        'domain_variants',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('target_domain', sa.String(255), nullable=False, comment='Legitimate domain being monitored'),
        sa.Column('variant_domain', sa.String(255), nullable=False, comment='Detected variant domain'),
        sa.Column('variant_type', sa.String(50), nullable=False, comment='Type: homoglyph, typo, tld_variation, combo_squatting, etc.'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true', comment='Whether domain currently resolves'),
        sa.Column('confidence_score', sa.Integer(), nullable=True, comment='Threat confidence score (0-100)'),
        sa.Column('threat_level', sa.String(20), nullable=True, comment='Threat level: safe, low, medium, high, critical'),
        sa.Column('scan_id', sa.Integer(), nullable=True, comment='Link to full scan if performed'),
        sa.Column('whois_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True, comment='WHOIS lookup results'),
        sa.Column('detection_method', sa.String(50), nullable=False, server_default='automated', comment='Detection method: automated, manual, ct_logs, etc.'),
        sa.Column('notes', sa.Text(), nullable=True, comment='Analyst notes and observations'),
        sa.Column('first_seen', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='First detection timestamp'),
        sa.Column('last_checked', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='Last verification timestamp'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('variant_domain')
    )

    # Indexes for domain_variants
    op.create_index('ix_domain_variants_target_domain', 'domain_variants', ['target_domain'])
    op.create_index('ix_domain_variants_variant_domain', 'domain_variants', ['variant_domain'])
    op.create_index('ix_domain_variants_variant_type', 'domain_variants', ['variant_type'])
    op.create_index('ix_domain_variants_is_active', 'domain_variants', ['is_active'])
    op.create_index('ix_domain_variants_threat_level', 'domain_variants', ['threat_level'])
    op.create_index('ix_domain_variants_first_seen', 'domain_variants', ['first_seen'])

    # ========== 2. CT Certificates Table (Certificate Transparency) ==========
    op.create_table(
        'ct_certificates',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('cert_id', sa.String(255), nullable=False, comment='Certificate ID from CT log'),
        sa.Column('fingerprint', sa.String(64), nullable=False, comment='SHA256 fingerprint'),
        sa.Column('issuer', sa.String(255), nullable=False, comment='Certificate issuer'),
        sa.Column('subject_cn', sa.String(255), nullable=False, comment='Subject Common Name'),
        sa.Column('san_domains', postgresql.ARRAY(sa.String()), nullable=False, comment='Subject Alternative Names (all domains)'),
        sa.Column('not_before', sa.DateTime(), nullable=False, comment='Certificate valid from'),
        sa.Column('not_after', sa.DateTime(), nullable=False, comment='Certificate valid until'),
        sa.Column('log_source', sa.String(50), nullable=False, comment='CT log source: crt.sh, google_argon, cloudflare_nimbus'),
        sa.Column('discovered_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='Discovery timestamp'),
        sa.Column('is_suspicious', sa.Boolean(), nullable=False, server_default='false', comment='Whether certificate is flagged as suspicious'),
        sa.Column('matched_keywords', postgresql.ARRAY(sa.String()), nullable=True, comment='Keywords that triggered detection'),
        sa.Column('confidence_score', sa.Integer(), nullable=True, comment='Threat confidence score (0-100)'),
        sa.Column('threat_level', sa.String(20), nullable=True, comment='Threat level: safe, low, medium, high, critical'),
        sa.Column('scan_triggered', sa.Boolean(), nullable=False, server_default='false', comment='Whether automatic scan was triggered'),
        sa.Column('raw_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True, comment='Raw certificate data from CT log'),
        sa.Column('notes', sa.Text(), nullable=True, comment='Analyst notes'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='Record creation timestamp'),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='Record update timestamp'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('cert_id'),
        sa.UniqueConstraint('fingerprint')
    )

    # Indexes for ct_certificates
    op.create_index('ix_ct_certificates_cert_id', 'ct_certificates', ['cert_id'])
    op.create_index('ix_ct_certificates_fingerprint', 'ct_certificates', ['fingerprint'])
    op.create_index('ix_ct_certificates_subject_cn', 'ct_certificates', ['subject_cn'])
    op.create_index('ix_ct_certificates_log_source', 'ct_certificates', ['log_source'])
    op.create_index('ix_ct_certificates_discovered_at', 'ct_certificates', ['discovered_at'])
    op.create_index('ix_ct_certificates_is_suspicious', 'ct_certificates', ['is_suspicious'])
    op.create_index('ix_ct_certificates_threat_level', 'ct_certificates', ['threat_level'])
    op.create_index('idx_ct_cert_suspicious_discovered', 'ct_certificates', ['is_suspicious', 'discovered_at'])
    op.create_index('idx_ct_cert_threat_level', 'ct_certificates', ['threat_level', 'discovered_at'])
    op.create_index('idx_ct_cert_scan_triggered', 'ct_certificates', ['scan_triggered', 'is_suspicious'])

    # ========== 3. Case Assignments Table (Team Collaboration) ==========
    op.create_table(
        'case_assignments',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=True, comment='Link to scan being investigated'),
        sa.Column('abuse_report_id', sa.Integer(), nullable=True, comment='Link to abuse report (if applicable)'),
        sa.Column('assigned_to_user_id', sa.Integer(), nullable=False, comment='Analyst assigned to investigate'),
        sa.Column('assigned_by_user_id', sa.Integer(), nullable=False, comment='Manager who assigned case'),
        sa.Column('status', sa.String(20), nullable=False, server_default='pending', comment='Status: pending, in_progress, completed, reassigned'),
        sa.Column('priority', sa.String(20), nullable=False, server_default='medium', comment='Priority: low, medium, high, critical'),
        sa.Column('due_date', sa.DateTime(), nullable=True, comment='Optional deadline for completion'),
        sa.Column('assigned_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='When case was assigned'),
        sa.Column('accepted_at', sa.DateTime(), nullable=True, comment='When analyst accepted assignment'),
        sa.Column('completed_at', sa.DateTime(), nullable=True, comment='When case was completed'),
        sa.Column('notes', sa.Text(), nullable=True, comment='Assignment notes from manager'),
        sa.Column('completion_summary', sa.Text(), nullable=True, comment='Summary provided by analyst on completion'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['abuse_report_id'], ['abuse_reports.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['assigned_to_user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['assigned_by_user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # Indexes for case_assignments
    op.create_index('ix_case_assignments_scan_id', 'case_assignments', ['scan_id'])
    op.create_index('ix_case_assignments_abuse_report_id', 'case_assignments', ['abuse_report_id'])
    op.create_index('ix_case_assignments_assigned_to_user_id', 'case_assignments', ['assigned_to_user_id'])
    op.create_index('ix_case_assignments_status', 'case_assignments', ['status'])
    op.create_index('ix_case_assignments_priority', 'case_assignments', ['priority'])
    op.create_index('ix_case_assignments_due_date', 'case_assignments', ['due_date'])
    op.create_index('ix_case_assignments_assigned_at', 'case_assignments', ['assigned_at'])
    op.create_index('ix_case_assignments_completed_at', 'case_assignments', ['completed_at'])
    op.create_index('idx_assignment_user_status', 'case_assignments', ['assigned_to_user_id', 'status'])
    op.create_index('idx_assignment_priority_status', 'case_assignments', ['priority', 'status'])
    op.create_index('idx_assignment_due_date', 'case_assignments', ['due_date', 'status'])

    # ========== 4. Notes Table (Team Collaboration) ==========
    op.create_table(
        'notes',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=True, comment='Link to scan (if note is on scan)'),
        sa.Column('abuse_report_id', sa.Integer(), nullable=True, comment='Link to abuse report (if note is on report)'),
        sa.Column('case_assignment_id', sa.Integer(), nullable=True, comment='Link to case assignment (if note is on assignment)'),
        sa.Column('author_user_id', sa.Integer(), nullable=False, comment='User who created note'),
        sa.Column('content', sa.Text(), nullable=False, comment='Note content (markdown supported)'),
        sa.Column('is_important', sa.Boolean(), nullable=False, server_default='false', comment='Whether note is flagged as important'),
        sa.Column('mentions', postgresql.ARRAY(sa.Integer()), nullable=True, comment='User IDs mentioned in note (@user)'),
        sa.Column('attachments', postgresql.ARRAY(sa.String()), nullable=True, comment='Attachment file paths (max 10MB each)'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='Note creation timestamp'),
        sa.Column('updated_at', sa.DateTime(), nullable=True, comment='Note last update timestamp'),
        sa.Column('is_archived', sa.Boolean(), nullable=False, server_default='false', comment='Soft delete flag (notes never hard deleted)'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['abuse_report_id'], ['abuse_reports.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['case_assignment_id'], ['case_assignments.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['author_user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # Indexes for notes
    op.create_index('ix_notes_scan_id', 'notes', ['scan_id'])
    op.create_index('ix_notes_abuse_report_id', 'notes', ['abuse_report_id'])
    op.create_index('ix_notes_case_assignment_id', 'notes', ['case_assignment_id'])
    op.create_index('ix_notes_author_user_id', 'notes', ['author_user_id'])
    op.create_index('ix_notes_is_important', 'notes', ['is_important'])
    op.create_index('ix_notes_created_at', 'notes', ['created_at'])
    op.create_index('ix_notes_is_archived', 'notes', ['is_archived'])
    op.create_index('idx_note_scan_created', 'notes', ['scan_id', 'created_at'])
    op.create_index('idx_note_report_created', 'notes', ['abuse_report_id', 'created_at'])
    op.create_index('idx_note_important', 'notes', ['is_important', 'created_at'])
    op.create_index('idx_note_archived', 'notes', ['is_archived', 'created_at'])


def downgrade() -> None:
    """Remove Sprint 4 tables."""
    op.drop_table('notes')
    op.drop_table('case_assignments')
    op.drop_table('ct_certificates')
    op.drop_table('domain_variants')
