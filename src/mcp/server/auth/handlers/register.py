from typing import TYPE_CHECKING
import secrets
import time
from uuid import uuid4
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata
from mcp.server.auth.settings import ClientRegistrationOptions

if TYPE_CHECKING:
    from mcp.server.auth.provider import OAuthAuthorizationServerProvider


async def build_and_register_client(
    provider: "OAuthAuthorizationServerProvider",
    client_metadata: OAuthClientMetadata,
    options: ClientRegistrationOptions,
    client_id: str | None = None,
) -> OAuthClientInformationFull:
    # Scope validation
    if client_metadata.scope is None and options.default_scopes is not None:
        client_metadata.scope = " ".join(options.default_scopes)
    elif client_metadata.scope is not None and options.valid_scopes is not None:
        requested_scopes = set(client_metadata.scope.split())
        valid_scopes = set(options.valid_scopes)
        if not requested_scopes.issubset(valid_scopes):
            raise ValueError(
                f"Requested scopes are not valid: {', '.join(requested_scopes - valid_scopes)}"
            )
    if set(client_metadata.grant_types) != {"authorization_code", "refresh_token"}:
        raise ValueError("grant_types must be authorization_code and refresh_token")

    client_id = client_id or str(uuid4())
    client_id_issued_at = int(time.time())
    
    client_secret = None
    client_secret_expires_at = None
    if options.enabled and client_metadata.token_endpoint_auth_method != "none":
        client_secret = secrets.token_hex(32)
        client_secret_expires_at = (
            client_id_issued_at + options.client_secret_expiry_seconds
            if options.client_secret_expiry_seconds is not None
            else None
        )

    client_info = OAuthClientInformationFull(
        client_id=client_id,
        client_id_issued_at=client_id_issued_at,
        client_secret=client_secret,
        client_secret_expires_at=client_secret_expires_at,
        redirect_uris=client_metadata.redirect_uris,
        token_endpoint_auth_method=client_metadata.token_endpoint_auth_method,
        grant_types=client_metadata.grant_types,
        response_types=client_metadata.response_types,
        client_name=client_metadata.client_name,
        client_uri=client_metadata.client_uri,
        logo_uri=client_metadata.logo_uri,
        scope=client_metadata.scope,
        contacts=client_metadata.contacts,
        tos_uri=client_metadata.tos_uri,
        policy_uri=client_metadata.policy_uri,
        jwks_uri=client_metadata.jwks_uri,
        jwks=client_metadata.jwks,
        software_id=client_metadata.software_id,
        software_version=client_metadata.software_version,
    )
    await provider.register_client(client_info)
    return client_info


import secrets
import time
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, RootModel, ValidationError
from starlette.requests import Request
from starlette.responses import Response

from mcp.server.auth.errors import stringify_pydantic_error
from mcp.server.auth.json_response import PydanticJSONResponse
from mcp.server.auth.provider import (
    OAuthAuthorizationServerProvider,
    RegistrationError,
    RegistrationErrorCode,
)
from mcp.server.auth.settings import ClientRegistrationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata


class RegistrationRequest(RootModel[OAuthClientMetadata]):
    # this wrapper is a no-op; it's just to separate out the types exposed to the
    # provider from what we use in the HTTP handler
    root: OAuthClientMetadata


class RegistrationErrorResponse(BaseModel):
    error: RegistrationErrorCode
    error_description: str | None


@dataclass
class RegistrationHandler:
    provider: OAuthAuthorizationServerProvider[Any, Any, Any]
    options: ClientRegistrationOptions

    async def handle(self, request: Request) -> Response:
        print("Handling client registration request")
        return PydanticJSONResponse(
            content=OAuthClientInformationFull(
                client_id=str(uuid4()),
                client_id_issued_at=int(time.time()),
                client_secret=secrets.token_hex(32),
                redirect_uris=["https://example.com/callback"],
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                client_name="Example Client",
                client_uri="https://example.com",
                logo_uri="https://example.com/logo.png",
                scope="read write",
                contacts=["test@s2.com"],
                tos_uri="https://example.com/tos",
                policy_uri="https://example.com/policy",
                jwks_uri="https://example.com/jwks",
                jwks=None,  # JWKS can be provided if needed
                software_id=None,
                software_version=None,  # Optional fields can be set to None
            ),
            status_code=201,
        )

        # Implements dynamic client registration as defined in https://datatracker.ietf.org/doc/html/rfc7591#section-3.1
        """ try:
            # Parse request body as JSON
            body = await request.json()
            client_metadata = OAuthClientMetadata.model_validate(body)
        except ValidationError as validation_error:
            return PydanticJSONResponse(
                content=RegistrationErrorResponse(
                    error="invalid_client_metadata",
                    error_description=stringify_pydantic_error(validation_error),
                ),
                status_code=400,
            )

        try:
            client_info = await build_and_register_client(self.provider, client_metadata, self.options)
            return PydanticJSONResponse(content=client_info, status_code=201)
        except ValueError as e:
            return PydanticJSONResponse(
                content=RegistrationErrorResponse(
                    error="invalid_client_metadata",
                    error_description=str(e),
                ),
                status_code=400,
            )
        except RegistrationError as e:
            return PydanticJSONResponse(
                content=RegistrationErrorResponse(
                    error=e.error, error_description=e.error_description
                ),
                status_code=400,
            ) """
