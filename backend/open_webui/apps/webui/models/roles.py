import logging
from typing import Optional
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Column, String, Text, BigInteger
from open_webui.apps.webui.internal.db import Base, get_db, JSONField
import time

log = logging.getLogger(__name__)

# Define standard tiers as constants
class RoleTiers:
    TIER_0 = "tier_0"  # Minimal access
    TIER_1 = "tier_1"  # Basic access
    TIER_2 = "tier_2"  # Enhanced access
    TIER_3 = "tier_3"  # Admin access

####################
# Role DB Schema
####################

class Role(Base):
    __tablename__ = "role"

    # This matches the role column in User table
    name = Column(String, primary_key=True)
    description = Column(Text, nullable=True)
    # Tier is required and defaults to TIER_0
    tier = Column(String, nullable=False, default=RoleTiers.TIER_0)
    created_at = Column(BigInteger)
    updated_at = Column(BigInteger)
    metadata = Column(JSONField, nullable=True)

class RoleModel(BaseModel):
    name: str
    description: Optional[str] = None
    tier: str = RoleTiers.TIER_0
    created_at: int  # timestamp in epoch
    updated_at: int  # timestamp in epoch
    metadata: Optional[dict] = None

    model_config = ConfigDict(from_attributes=True)

####################
# Forms
####################

class CreateRoleForm(BaseModel):
    name: str
    description: Optional[str] = None
    tier: str = RoleTiers.TIER_0
    metadata: Optional[dict] = None

class UpdateRoleForm(BaseModel):
    description: Optional[str] = None
    tier: str
    metadata: Optional[dict] = None

class TierUpdateForm(BaseModel):
    tier: str

####################
# Role Table Operations
####################

class RolesTable:
    def create_role(
        self,
        name: str,
        tier: str = RoleTiers.TIER_0,
        description: Optional[str] = None,
        metadata: Optional[dict] = None
    ) -> Optional[RoleModel]:
        try:
            with get_db() as db:
                current_time = int(time.time())
                role = RoleModel(
                    name=name,
                    description=description,
                    tier=tier,
                    created_at=current_time,
                    updated_at=current_time,
                    metadata=metadata
                )
                result = Role(**role.model_dump())
                db.add(result)
                db.commit()
                db.refresh(result)
                return RoleModel.model_validate(result)
        except Exception:
            return None

    def get_role_by_name(self, name: str) -> Optional[RoleModel]:
        try:
            with get_db() as db:
                role = db.query(Role).filter_by(name=name).first()
                return RoleModel.model_validate(role) if role else None
        except Exception:
            return None

    def get_roles_by_tier(self, tier: str) -> list[RoleModel]:
        try:
            with get_db() as db:
                roles = db.query(Role).filter_by(tier=tier).all()
                return [RoleModel.model_validate(role) for role in roles]
        except Exception:
            return []

    def get_all_roles(self) -> list[RoleModel]:
        try:
            with get_db() as db:
                roles = db.query(Role).all()
                return [RoleModel.model_validate(role) for role in roles]
        except Exception:
            return []

    def update_role(
        self,
        name: str,
        tier: str,
        description: Optional[str] = None,
        metadata: Optional[dict] = None
    ) -> Optional[RoleModel]:
        try:
            with get_db() as db:
                updates = {
                    "updated_at": int(time.time()),
                    "tier": tier  # Tier is required
                }
                if description is not None:
                    updates["description"] = description
                if metadata is not None:
                    updates["metadata"] = metadata

                db.query(Role).filter_by(name=name).update(updates)
                db.commit()

                role = db.query(Role).filter_by(name=name).first()
                return RoleModel.model_validate(role) if role else None
        except Exception:
            return None

    def update_role_tier(self, name: str, tier: str) -> Optional[RoleModel]:
        """
        Update the tier of a role
        Returns the updated role or None if the update failed
        """
        try:
            with get_db() as db:
                updates = {
                    "tier": tier,
                    "updated_at": int(time.time())
                }
                
                result = db.query(Role).filter_by(name=name).update(updates)
                if result == 0:  # No role found with this name
                    return None
                    
                db.commit()
                role = db.query(Role).filter_by(name=name).first()
                return RoleModel.model_validate(role)
        except Exception:
            return None

    def bulk_update_tiers(self, tier_updates: dict[str, str]) -> dict[str, bool]:
        """
        Update tiers for multiple roles at once
        Args:
            tier_updates: Dictionary mapping role names to their new tiers
        Returns:
            Dictionary mapping role names to update success status
        """
        results = {}
        try:
            with get_db() as db:
                for role_name, new_tier in tier_updates.items():
                    try:
                        result = db.query(Role).filter_by(name=role_name).update({
                            "tier": new_tier,
                            "updated_at": int(time.time())
                        })
                        results[role_name] = result > 0
                    except Exception:
                        results[role_name] = False
                db.commit()
        except Exception:
            # If there's a transaction error, mark all remaining updates as failed
            for role_name in tier_updates:
                if role_name not in results:
                    results[role_name] = False
        return results

    def delete_role(self, name: str) -> bool:
        try:
            with get_db() as db:
                result = db.query(Role).filter_by(name=name).delete()
                db.commit()
                return result > 0
        except Exception:
            return False

    def role_exists(self, name: str) -> bool:
        try:
            with get_db() as db:
                return db.query(Role).filter_by(name=name).first() is not None
        except Exception:
            return False

# Singleton instance
Roles = RolesTable()

# Initialize default roles
def initialize_default_roles():
    default_roles = [
        {
            "name": "admin",
            "description": "Administrator with full system access",
            "tier": RoleTiers.TIER_3,
            "metadata": {"is_system_role": True}
        },
        {
            "name": "user",
            "description": "Standard user with basic access",
            "tier": RoleTiers.TIER_1,
            "metadata": {"is_system_role": True}
        },
        {
            "name": "pending",
            "description": "New user awaiting approval",
            "tier": RoleTiers.TIER_0,
            "metadata": {"is_system_role": True}
        }
    ]

    for role_data in default_roles:
        if not Roles.role_exists(role_data["name"]):
            Roles.create_role(**role_data)