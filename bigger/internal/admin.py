from fastapi import APIRouter, Depends, HTTPException

from ..dependencies import get_token_header

router = APIRouter()


@router.post("/")
async def update_admin():
    return {"message": "Admin has been updated"}
