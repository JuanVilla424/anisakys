"""Initial schema with 8 core tables.

Revision ID: 001_initial_schema
Revises:
Create Date: 2026-01-03 19:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create all 8 core tables for Sprint 1."""

    # 1. Create users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=255), nullable=True),
        sa.Column('tier', sa.String(length=20), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('email_verified', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('last_login_at', sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "tier IN ('community', 'professional', 'business', 'enterprise')",
            name='check_tier'
        ),
        sa.CheckConstraint(
            "status IN ('active', 'suspended', 'cancelled')",
            name='check_status'
        ),
        sa.CheckConstraint(
            "email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}$'",
            name='check_email_format'
        ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_users_email', 'users', ['email'], unique=False)
    op.create_index('idx_users_tier', 'users', ['tier'], unique=False)
    op.create_index('idx_users_status', 'users', ['status'], unique=False)
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)

    # 2. Create api_keys table
    op.create_table(
        'api_keys',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('key_hash', sa.String(length=255), nullable=False),
        sa.Column('key_prefix', sa.String(length=20), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=True),
        sa.Column('scopes', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('rate_limit_tier', sa.String(length=20), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_api_keys_is_active', 'api_keys', ['is_active'], unique=False)
    op.create_index('idx_api_keys_key_hash', 'api_keys', ['key_hash'], unique=False)
    op.create_index('idx_api_keys_user_id', 'api_keys', ['user_id'], unique=False)
    op.create_index(
        'idx_api_keys_expires_at',
        'api_keys',
        ['expires_at'],
        unique=False,
        postgresql_where=sa.text('expires_at IS NOT NULL')
    )
    op.create_index(op.f('ix_api_keys_expires_at'), 'api_keys', ['expires_at'], unique=False)
    op.create_index(op.f('ix_api_keys_id'), 'api_keys', ['id'], unique=False)
    op.create_index(op.f('ix_api_keys_key_hash'), 'api_keys', ['key_hash'], unique=True)
    op.create_index(op.f('ix_api_keys_user_id'), 'api_keys', ['user_id'], unique=False)

    # 3. Create scans table
    op.create_table(
        'scans',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('url_hash', sa.String(length=64), nullable=False),
        sa.Column('scan_type', sa.String(length=20), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('threat_level', sa.String(length=20), nullable=True),
        sa.Column('confidence_score', sa.Numeric(precision=5, scale=2), nullable=True),
        sa.Column('is_phishing', sa.Boolean(), nullable=True),
        sa.Column('virustotal_result', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('urlvoid_result', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('phishtank_result', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('grinder_result', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('screenshot_url', sa.Text(), nullable=True),
        sa.Column('screenshot_hash', sa.String(length=64), nullable=True),
        sa.Column('html_snapshot_url', sa.Text(), nullable=True),
        sa.Column('domain', sa.String(length=255), nullable=True),
        sa.Column('ip_address', postgresql.INET(), nullable=True),
        sa.Column('country_code', sa.String(length=2), nullable=True),
        sa.Column('hosting_provider', sa.String(length=255), nullable=True),
        sa.Column('scan_started_at', sa.DateTime(), nullable=True),
        sa.Column('scan_completed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('scan_duration_ms', sa.Integer(), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'completed', 'failed')",
            name='check_status'
        ),
        sa.CheckConstraint(
            "threat_level IN ('safe', 'low', 'medium', 'high', 'critical')",
            name='check_threat_level'
        ),
        sa.CheckConstraint(
            'confidence_score BETWEEN 0 AND 100',
            name='check_confidence_score'
        ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_scans_created_at', 'scans', ['created_at'], unique=False, postgresql_using='btree')
    op.create_index('idx_scans_domain', 'scans', ['domain'], unique=False)
    op.create_index('idx_scans_status', 'scans', ['status'], unique=False)
    op.create_index('idx_scans_threat_level', 'scans', ['threat_level'], unique=False)
    op.create_index('idx_scans_url_hash', 'scans', ['url_hash'], unique=False)
    op.create_index('idx_scans_user_created', 'scans', ['user_id', 'created_at'], unique=False)
    op.create_index('idx_scans_user_id', 'scans', ['user_id'], unique=False)
    op.create_index(
        'idx_scans_virustotal_result',
        'scans',
        ['virustotal_result'],
        unique=False,
        postgresql_using='gin'
    )
    op.create_index(op.f('ix_scans_created_at'), 'scans', ['created_at'], unique=False)
    op.create_index(op.f('ix_scans_domain'), 'scans', ['domain'], unique=False)
    op.create_index(op.f('ix_scans_id'), 'scans', ['id'], unique=False)
    op.create_index(op.f('ix_scans_status'), 'scans', ['status'], unique=False)
    op.create_index(op.f('ix_scans_threat_level'), 'scans', ['threat_level'], unique=False)
    op.create_index(op.f('ix_scans_url_hash'), 'scans', ['url_hash'], unique=False)
    op.create_index(op.f('ix_scans_user_id'), 'scans', ['user_id'], unique=False)

    # 4. Create batch_scans table
    op.create_table(
        'batch_scans',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('batch_name', sa.String(length=255), nullable=True),
        sa.Column('total_urls', sa.Integer(), nullable=False),
        sa.Column('completed_urls', sa.Integer(), nullable=False),
        sa.Column('failed_urls', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('progress_percentage', sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'completed', 'failed')",
            name='check_batch_status'
        ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_batch_scans_created_at', 'batch_scans', ['created_at'], unique=False)
    op.create_index('idx_batch_scans_status', 'batch_scans', ['status'], unique=False)
    op.create_index('idx_batch_scans_user_id', 'batch_scans', ['user_id'], unique=False)
    op.create_index(op.f('ix_batch_scans_created_at'), 'batch_scans', ['created_at'], unique=False)
    op.create_index(op.f('ix_batch_scans_id'), 'batch_scans', ['id'], unique=False)
    op.create_index(op.f('ix_batch_scans_status'), 'batch_scans', ['status'], unique=False)
    op.create_index(op.f('ix_batch_scans_user_id'), 'batch_scans', ['user_id'], unique=False)

    # 5. Create abuse_reports table
    op.create_table(
        'abuse_reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('report_type', sa.String(length=50), nullable=False),
        sa.Column('recipient_email', postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column('subject', sa.String(length=500), nullable=True),
        sa.Column('body', sa.Text(), nullable=True),
        sa.Column('attachments', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('icann_sla_deadline', sa.DateTime(), nullable=True),
        sa.Column('icann_sla_status', sa.String(length=20), nullable=True),
        sa.Column('sla_alert_sent', sa.Boolean(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('submitted_at', sa.DateTime(), nullable=True),
        sa.Column('acknowledged_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('response_received', sa.Boolean(), nullable=False),
        sa.Column('response_text', sa.Text(), nullable=True),
        sa.Column('response_received_at', sa.DateTime(), nullable=True),
        sa.Column('manual_submission', sa.Boolean(), nullable=False),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "report_type IN ('phishing', 'malware', 'spam', 'copyright', 'other')",
            name='check_report_type'
        ),
        sa.CheckConstraint(
            "status IN ('draft', 'submitted', 'acknowledged', 'resolved', 'rejected')",
            name='check_report_status'
        ),
        sa.CheckConstraint(
            "icann_sla_status IN ('compliant', 'approaching', 'overdue', 'waived')",
            name='check_icann_sla_status'
        ),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_abuse_reports_icann_sla_deadline', 'abuse_reports', ['icann_sla_deadline'], unique=False)
    op.create_index('idx_abuse_reports_scan_id', 'abuse_reports', ['scan_id'], unique=False)
    op.create_index('idx_abuse_reports_status', 'abuse_reports', ['status'], unique=False)
    op.create_index('idx_abuse_reports_submitted_at', 'abuse_reports', ['submitted_at'], unique=False)
    op.create_index('idx_abuse_reports_user_id', 'abuse_reports', ['user_id'], unique=False)
    op.create_index(op.f('ix_abuse_reports_icann_sla_deadline'), 'abuse_reports', ['icann_sla_deadline'], unique=False)
    op.create_index(op.f('ix_abuse_reports_id'), 'abuse_reports', ['id'], unique=False)
    op.create_index(op.f('ix_abuse_reports_scan_id'), 'abuse_reports', ['scan_id'], unique=False)
    op.create_index(op.f('ix_abuse_reports_status'), 'abuse_reports', ['status'], unique=False)
    op.create_index(op.f('ix_abuse_reports_submitted_at'), 'abuse_reports', ['submitted_at'], unique=False)
    op.create_index(op.f('ix_abuse_reports_user_id'), 'abuse_reports', ['user_id'], unique=False)

    # 6. Create domain_watchlist table
    op.create_table(
        'domain_watchlist',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=False),
        sa.Column('brand_name', sa.String(length=255), nullable=True),
        sa.Column('monitoring_enabled', sa.Boolean(), nullable=False),
        sa.Column('alert_threshold', sa.String(length=20), nullable=False),
        sa.Column('check_typosquatting', sa.Boolean(), nullable=False),
        sa.Column('check_certificate_transparency', sa.Boolean(), nullable=False),
        sa.Column('check_social_media', sa.Boolean(), nullable=False),
        sa.Column('notify_email', sa.Boolean(), nullable=False),
        sa.Column('notify_webhook', sa.Boolean(), nullable=False),
        sa.Column('webhook_url', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_checked_at', sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "alert_threshold IN ('low', 'medium', 'high', 'critical')",
            name='check_alert_threshold'
        ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'domain', name='unique_user_domain')
    )
    op.create_index('idx_watchlist_domain', 'domain_watchlist', ['domain'], unique=False)
    op.create_index('idx_watchlist_monitoring_enabled', 'domain_watchlist', ['monitoring_enabled'], unique=False)
    op.create_index('idx_watchlist_user_id', 'domain_watchlist', ['user_id'], unique=False)
    op.create_index(op.f('ix_domain_watchlist_domain'), 'domain_watchlist', ['domain'], unique=False)
    op.create_index(op.f('ix_domain_watchlist_id'), 'domain_watchlist', ['id'], unique=False)
    op.create_index(op.f('ix_domain_watchlist_monitoring_enabled'), 'domain_watchlist', ['monitoring_enabled'], unique=False)
    op.create_index(op.f('ix_domain_watchlist_user_id'), 'domain_watchlist', ['user_id'], unique=False)

    # 7. Create audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('resource_type', sa.String(length=50), nullable=True),
        sa.Column('resource_id', sa.Integer(), nullable=True),
        sa.Column('ip_address', postgresql.INET(), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('request_method', sa.String(length=10), nullable=True),
        sa.Column('request_path', sa.Text(), nullable=True),
        sa.Column('old_values', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('new_values', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.CheckConstraint("status IN ('success', 'failure', 'error')", name='check_status'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_audit_logs_action', 'audit_logs', ['action'], unique=False)
    op.create_index('idx_audit_logs_resource', 'audit_logs', ['resource_type', 'resource_id'], unique=False)
    op.create_index('idx_audit_logs_timestamp', 'audit_logs', ['timestamp'], unique=False, postgresql_using='btree')
    op.create_index('idx_audit_logs_user_id', 'audit_logs', ['user_id'], unique=False)
    op.create_index(op.f('ix_audit_logs_action'), 'audit_logs', ['action'], unique=False)
    op.create_index(op.f('ix_audit_logs_id'), 'audit_logs', ['id'], unique=False)
    op.create_index(op.f('ix_audit_logs_timestamp'), 'audit_logs', ['timestamp'], unique=False)
    op.create_index(op.f('ix_audit_logs_user_id'), 'audit_logs', ['user_id'], unique=False)

    # 8. Create usage_tracking table
    op.create_table(
        'usage_tracking',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('tier', sa.String(length=20), nullable=False),
        sa.Column('resource_type', sa.String(length=50), nullable=False),
        sa.Column('quantity', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=True),
        sa.Column('api_endpoint', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('billing_period', sa.Date(), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_usage_resource_type', 'usage_tracking', ['resource_type'], unique=False)
    op.create_index('idx_usage_timestamp', 'usage_tracking', ['timestamp'], unique=False)
    op.create_index('idx_usage_user_period', 'usage_tracking', ['user_id', 'billing_period'], unique=False)
    op.create_index(op.f('ix_usage_tracking_id'), 'usage_tracking', ['id'], unique=False)
    op.create_index(op.f('ix_usage_tracking_resource_type'), 'usage_tracking', ['resource_type'], unique=False)
    op.create_index(op.f('ix_usage_tracking_timestamp'), 'usage_tracking', ['timestamp'], unique=False)
    op.create_index(op.f('ix_usage_tracking_user_id'), 'usage_tracking', ['user_id'], unique=False)


def downgrade() -> None:
    """Drop all 8 tables in reverse dependency order."""
    op.drop_table('usage_tracking')
    op.drop_table('audit_logs')
    op.drop_table('domain_watchlist')
    op.drop_table('abuse_reports')
    op.drop_table('batch_scans')
    op.drop_table('scans')
    op.drop_table('api_keys')
    op.drop_table('users')
