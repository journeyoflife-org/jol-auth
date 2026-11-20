"""MFA service — TOTP enrolment, verification, and factor management.

Uses pyotp for TOTP generation and verification. Secrets are encrypted
at rest with AES-256-GCM (via Fernet) so they can be recovered for
verification while remaining protected in the event of a database leak.
"""

from uuid import UUID

import pyotp
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.exceptions import NotFoundError, UnauthorizedError
from app.models.mfa_factor import MFAFactor
from app.security.secret_encryption import (
    SecretEncryptor,
    generate_recovery_codes,
    get_encryptor,
    hash_recovery_code,
)


class MFAService:
    """Manages TOTP multi-factor authentication within a tenant boundary."""

    def __init__(self, db: AsyncSession, encryptor: SecretEncryptor | None = None) -> None:
        self._db = db
        self._encryptor = encryptor

    def _get_encryptor(self) -> SecretEncryptor:
        """Get the encryptor instance (lazy init)."""
        if self._encryptor is not None:
            return self._encryptor
        return get_encryptor()

    async def enroll_totp(self, tenant_id: UUID, user_id: UUID) -> dict[str, str | int]:
        """Generate a TOTP secret and provisioning URI for enrolment.

        The raw secret is returned to the client for QR code display but
        only the **encrypted** secret is persisted.  The factor is created
        in an unverified state until :meth:`verify_totp` succeeds.

        Returns a dict with: ``secret``, ``provisioning_uri``, ``issuer``,
        ``digits``, ``period``.
        """
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(
            secret,
            digits=settings.mfa_totp_digits,
            interval=settings.mfa_totp_period,
        )
        provisioning_uri = totp.provisioning_uri(
            name=str(user_id),
            issuer_name=settings.mfa_totp_issuer,
        )

        # Encrypt the secret with AES-256-GCM (Fernet) before storage
        encryptor = self._get_encryptor()
        encrypted_secret = encryptor.encrypt(secret)

        factor = MFAFactor(
            tenant_id=tenant_id,
            user_id=user_id,
            factor_type="totp",
            secret_encrypted=encrypted_secret,
            is_verified=False,
        )
        self._db.add(factor)
        await self._db.commit()
        await self._db.refresh(factor)

        return {
            "secret": secret,
            "provisioning_uri": provisioning_uri,
            "issuer": settings.mfa_totp_issuer,
            "digits": settings.mfa_totp_digits,
            "period": settings.mfa_totp_period,
        }

    async def verify_totp(self, tenant_id: UUID, user_id: UUID, code: str) -> bool:
        """Verify a TOTP code against the user's enrolled factor.

        The encrypted secret is decrypted in memory, used for TOTP
        verification, and never persisted in plaintext.

        On first successful verification, the factor is marked as verified.
        Returns ``True`` on success.

        Raises:
            NotFoundError: If no TOTP factor is enrolled.
            UnauthorizedError: If the code is invalid.
        """
        stmt = select(MFAFactor).where(
            MFAFactor.tenant_id == tenant_id,
            MFAFactor.user_id == user_id,
            MFAFactor.factor_type == "totp",
        )
        result = await self._db.execute(stmt)
        factor = result.scalar_one_or_none()

        if factor is None:
            raise NotFoundError(detail="No TOTP factor enrolled.")

        # Decrypt the secret in memory for verification
        encryptor = self._get_encryptor()
        raw_secret = encryptor.decrypt(factor.secret_encrypted)

        totp = pyotp.TOTP(
            raw_secret,
            digits=settings.mfa_totp_digits,
            interval=settings.mfa_totp_period,
        )
        if totp.verify(code):
            if not factor.is_verified:
                factor.is_verified = True
                await self._db.commit()
            return True

        raise UnauthorizedError(detail="Invalid TOTP code.")

    async def generate_recovery_codes(self, tenant_id: UUID, user_id: UUID) -> list[str]:
        """Generate one-time recovery codes for MFA bypass.

        Returns the raw codes (shown to user once).  Only SHA-256 hashes
        are stored in the database.

        Raises:
            NotFoundError: If no verified TOTP factor is enrolled.
        """
        # Verify user has a verified MFA factor
        stmt = select(MFAFactor).where(
            MFAFactor.tenant_id == tenant_id,
            MFAFactor.user_id == user_id,
            MFAFactor.factor_type == "totp",
            MFAFactor.is_verified.is_(True),
        )
        result = await self._db.execute(stmt)
        factor = result.scalar_one_or_none()

        if factor is None:
            raise NotFoundError(detail="No verified TOTP factor enrolled.")

        codes = generate_recovery_codes(count=10)
        # Store hashes (comma-separated for simplicity; normalize in future migration)
        factor.recovery_codes = ",".join(hash_recovery_code(c) for c in codes)
        await self._db.commit()

        return codes

    async def verify_recovery_code(self, tenant_id: UUID, user_id: UUID, code: str) -> bool:
        """Verify a recovery code and remove it after use (single-use).

        Raises:
            NotFoundError: If no recovery codes are set.
            UnauthorizedError: If the code is invalid or already used.
        """
        stmt = select(MFAFactor).where(
            MFAFactor.tenant_id == tenant_id,
            MFAFactor.user_id == user_id,
            MFAFactor.factor_type == "totp",
        )
        result = await self._db.execute(stmt)
        factor = result.scalar_one_or_none()

        if factor is None or not factor.recovery_codes:
            raise NotFoundError(detail="No recovery codes set.")

        code_hash = hash_recovery_code(code)
        stored_hashes = [h.strip() for h in factor.recovery_codes.split(",") if h.strip()]

        if code_hash not in stored_hashes:
            raise UnauthorizedError(detail="Invalid recovery code.")

        # Remove the used code (single-use)
        stored_hashes.remove(code_hash)
        factor.recovery_codes = ",".join(stored_hashes) if stored_hashes else None
        await self._db.commit()

        return True

    async def list_factors(self, tenant_id: UUID, user_id: UUID) -> list[MFAFactor]:
        """List enrolled MFA factors for a user within a tenant."""
        stmt = (
            select(MFAFactor)
            .where(MFAFactor.tenant_id == tenant_id, MFAFactor.user_id == user_id)
            .order_by(MFAFactor.created_at)
        )
        result = await self._db.execute(stmt)
        return list(result.scalars().all())

    async def remove_factor(self, factor_id: UUID, tenant_id: UUID, user_id: UUID) -> None:
        """Remove an enrolled MFA factor. Tenant-scoped."""
        stmt = select(MFAFactor).where(
            MFAFactor.id == factor_id,
            MFAFactor.tenant_id == tenant_id,
            MFAFactor.user_id == user_id,
        )
        result = await self._db.execute(stmt)
        factor = result.scalar_one_or_none()
        if factor is None:
            raise NotFoundError(detail="MFA factor not found.")
        await self._db.delete(factor)
        await self._db.commit()

    async def reset_mfa(self, tenant_id: UUID, user_id: UUID) -> None:
        """Remove all MFA factors for a user (admin-initiated reset).

        This is a break-glass operation that should be audit-logged by
        the caller.  All TOTP factors and recovery codes are deleted.
        """
        stmt = select(MFAFactor).where(
            MFAFactor.tenant_id == tenant_id,
            MFAFactor.user_id == user_id,
        )
        result = await self._db.execute(stmt)
        factors = result.scalars().all()

        for factor in factors:
            await self._db.delete(factor)
        await self._db.commit()
