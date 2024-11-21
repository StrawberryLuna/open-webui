import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from open_webui.env import SRC_LOG_LEVELS
from open_webui.constants import ERROR_MESSAGES
from open_webui.utils.utils import get_admin_user, get_verified_user
from open_webui.apps.webui.models.roles import Roles, RoleModel, CreateRoleForm, UpdateRoleForm, TierUpdateForm, RoleTiers

log = logging.getLogger(__name__)
log.setLevel(SRC_LOG_LEVELS["MODELS"])

router = APIRouter()

############################
# GetRoles
############################

@router.get("/", response_model=list[RoleModel])
async def get_roles(user=Depends(get_admin_user)):
    """Get all roles. Admin only."""
    return Roles.get_all_roles()

############################
# GetRoleByName
############################

@router.get("/{role_name}", response_model=Optional[RoleModel])
async def get_role_by_name(role_name: str, user=Depends(get_verified_user)):
    """Get a specific role by name."""
    role = Roles.get_role_by_name(role_name)
    if role:
        return role
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=ERROR_MESSAGES.ROLE_NOT_FOUND
    )

############################
# GetRolesByTier
############################

@router.get("/tier/{tier}", response_model=list[RoleModel])
async def get_roles_by_tier(tier: str, user=Depends(get_admin_user)):
    """Get all roles with a specific tier. Admin only."""
    return Roles.get_roles_by_tier(tier)

############################
# CreateRole
############################

@router.post("/create", response_model=RoleModel)
async def create_role(form_data: CreateRoleForm, user=Depends(get_admin_user)):
    """Create a new role. Admin only."""
    if Roles.role_exists(form_data.name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.ROLE_ALREADY_EXISTS
        )
    
    role = Roles.create_role(
        name=form_data.name,
        description=form_data.description,
        tier=form_data.tier,
        metadata=form_data.metadata
    )
    
    if role:
        return role
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=ERROR_MESSAGES.ROLE_CREATE_ERROR
    )

############################
# UpdateRole
############################

@router.post("/{role_name}/update", response_model=RoleModel)
async def update_role(
    role_name: str,
    form_data: UpdateRoleForm,
    user=Depends(get_admin_user)
):
    """Update an existing role. Admin only."""
    # Prevent updating system roles
    role = Roles.get_role_by_name(role_name)
    if role and role.metadata and role.metadata.get("is_system_role"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ERROR_MESSAGES.SYSTEM_ROLE_UPDATE_PROHIBITED
        )
    
    updated_role = Roles.update_role(
        name=role_name,
        description=form_data.description,
        tier=form_data.tier,
        metadata=form_data.metadata
    )
    
    if updated_role:
        return updated_role
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=ERROR_MESSAGES.ROLE_NOT_FOUND
    )

############################
# UpdateRoleTier
############################

@router.post("/{role_name}/tier", response_model=RoleModel)
async def update_role_tier(
    role_name: str,
    form_data: TierUpdateForm,
    user=Depends(get_admin_user)
):
    """Update just the tier of a role. Admin only."""
    # Prevent updating system roles
    role = Roles.get_role_by_name(role_name)
    if role and role.metadata and role.metadata.get("is_system_role"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ERROR_MESSAGES.SYSTEM_ROLE_UPDATE_PROHIBITED
        )
    
    updated_role = Roles.update_role_tier(role_name, form_data.tier)
    if updated_role:
        return updated_role
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=ERROR_MESSAGES.ROLE_NOT_FOUND
    )

############################
# BulkUpdateTiers
############################

class BulkTierUpdate(BaseModel):
    updates: dict[str, str]

class BulkUpdateResponse(BaseModel):
    results: dict[str, bool]

@router.post("/bulk-update-tiers", response_model=BulkUpdateResponse)
async def bulk_update_tiers(
    form_data: BulkTierUpdate,
    user=Depends(get_admin_user)
):
    """Bulk update tiers for multiple roles. Admin only."""
    # Check for system roles in the update list
    for role_name in form_data.updates.keys():
        role = Roles.get_role_by_name(role_name)
        if role and role.metadata and role.metadata.get("is_system_role"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Cannot update system role: {role_name}"
            )
    
    results = Roles.bulk_update_tiers(form_data.updates)
    return BulkUpdateResponse(results=results)

############################
# DeleteRole
############################

@router.delete("/{role_name}")
async def delete_role(role_name: str, user=Depends(get_admin_user)):
    """Delete a role. Admin only."""
    # Prevent deleting system roles
    role = Roles.get_role_by_name(role_name)
    if role and role.metadata and role.metadata.get("is_system_role"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ERROR_MESSAGES.SYSTEM_ROLE_DELETE_PROHIBITED
        )
    
    if Roles.delete_role(role_name):
        return {"message": "Role deleted successfully"}
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=ERROR_MESSAGES.ROLE_NOT_FOUND
    )

############################
# GetAvailableTiers
############################

class AvailableTiers(BaseModel):
    tiers: list[str]
    descriptions: dict[str, str]

@router.get("/system/available-tiers", response_model=AvailableTiers)
async def get_available_tiers(user=Depends(get_verified_user)):
    """Get list of available tiers and their descriptions."""
    return AvailableTiers(
        tiers=[
            RoleTiers.TIER_0,
            RoleTiers.TIER_1,
            RoleTiers.TIER_2,
            RoleTiers.TIER_3
        ],
        descriptions={
            RoleTiers.TIER_0: "Minimal access - Basic view permissions only",
            RoleTiers.TIER_1: "Basic access - Standard user permissions",
            RoleTiers.TIER_2: "Enhanced access - Advanced user permissions",
            RoleTiers.TIER_3: "Admin access - Full system access"
        }
    )