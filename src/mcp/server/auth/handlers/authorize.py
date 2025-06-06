import logging
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import AnyHttpUrl, AnyUrl, BaseModel, Field, RootModel, ValidationError
from starlette.datastructures import FormData, QueryParams
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from mcp.server.auth.errors import (
    stringify_pydantic_error,
)
from mcp.server.auth.json_response import PydanticJSONResponse
from mcp.server.auth.provider import (
    AuthorizationErrorCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    construct_redirect_uri,
)
from mcp.shared.auth import (
    InvalidRedirectUriError,
    InvalidScopeError,
)

logger = logging.getLogger(__name__)


class AuthorizationRequest(BaseModel):
    # See https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
    client_id: str = Field(..., description="The client ID")
    redirect_uri: AnyHttpUrl | None = Field(
        None, description="URL to redirect to after authorization"
    )

    # see OAuthClientMetadata; we only support `code`
    response_type: Literal["code"] = Field(
        ..., description="Must be 'code' for authorization code flow"
    )
    code_challenge: str = Field(..., description="PKCE code challenge")
    code_challenge_method: Literal["S256"] = Field(
        "S256", description="PKCE code challenge method, must be S256"
    )
    state: str | None = Field(None, description="Optional state parameter")
    scope: str | None = Field(
        None,
        description="Optional scope; if specified, should be "
        "a space-separated list of scope strings",
    )


class AuthorizationErrorResponse(BaseModel):
    error: AuthorizationErrorCode
    error_description: str | None
    error_uri: AnyUrl | None = None
    # must be set if provided in the request
    state: str | None = None


def best_effort_extract_string(
    key: str, params: None | FormData | QueryParams
) -> str | None:
    if params is None:
        return None
    value = params.get(key)
    if isinstance(value, str):
        return value
    return None


class AnyHttpUrlModel(RootModel[AnyHttpUrl]):
    root: AnyHttpUrl


@dataclass
class AuthorizationHandler:
    provider: OAuthAuthorizationServerProvider[Any, Any, Any]

    async def handle_get(self, request: Request) -> Response:
        """Handle GET /authorize. Register client if not found."""
        state = None
        redirect_uri = None
        client = None
        params = request.query_params

        async def error_response(
            error: AuthorizationErrorCode,
            error_description: str | None,
            attempt_load_client: bool = True,
        ):
            nonlocal client, redirect_uri, state
            if client is None and attempt_load_client:
                client_id = best_effort_extract_string("client_id", params)
                client = client_id and await self.provider.get_client(client_id)
            if redirect_uri is None and client:
                try:
                    # QueryParams is always not None, so just check key
                    if "redirect_uri" not in params:
                        raw_redirect_uri = None
                    else:
                        raw_redirect_uri = AnyHttpUrlModel.model_validate(
                            best_effort_extract_string("redirect_uri", params)
                        ).root
                    redirect_uri = client.validate_redirect_uri(raw_redirect_uri)
                except (ValidationError, InvalidRedirectUriError):
                    pass
            if state is None:
                state = best_effort_extract_string("state", params)
            error_resp = AuthorizationErrorResponse(
                error=error,
                error_description=error_description,
                state=state,
            )
            if redirect_uri and client:
                return RedirectResponse(
                    url=construct_redirect_uri(
                        str(redirect_uri), **error_resp.model_dump(exclude_none=True)
                    ),
                    status_code=302,
                    headers={"Cache-Control": "no-store"},
                )
            else:
                return PydanticJSONResponse(
                    status_code=400,
                    content=error_resp,
                    headers={"Cache-Control": "no-store"},
                )

        # Parse and validate request
        state = best_effort_extract_string("state", params)
        try:
            auth_request = AuthorizationRequest.model_validate(params)
            state = auth_request.state
        except ValidationError as validation_error:
            error: AuthorizationErrorCode = "invalid_request"
            for e in validation_error.errors():
                if e["loc"] == ("response_type",) and e["type"] == "literal_error":
                    error = "unsupported_response_type"
                    break
            return await error_response(
                error, stringify_pydantic_error(validation_error)
            )

        # Try to get client
        client = await self.provider.get_client(auth_request.client_id)
        if not client:
            from mcp.server.auth.handlers.register import build_and_register_client
            from mcp.server.auth.settings import ClientRegistrationOptions
            from mcp.shared.auth import OAuthClientMetadata

            client_metadata = OAuthClientMetadata(
                client_name=auth_request.client_id,
                redirect_uris=(
                    [auth_request.redirect_uri] if auth_request.redirect_uri else []
                ),
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                scope=auth_request.scope,
            )
            registration_options = ClientRegistrationOptions(
                enabled=True,
                default_scopes=[auth_request.scope] if auth_request.scope else [],
            )
            try:
                await build_and_register_client(
                    self.provider,
                    client_metadata,
                    registration_options,
                    client_id=auth_request.client_id,
                )
            except ValueError as e:
                return await error_response(
                    error="invalid_request",
                    error_description=f"Client registration failed: {e}",
                    attempt_load_client=False,
                )
            except Exception as e:
                return await error_response(
                    error="invalid_request",
                    error_description=f"Client registration failed: {e}",
                    attempt_load_client=False,
                )
            # Try to get client again
            client = await self.provider.get_client(auth_request.client_id)
            print(f"Client {auth_request.client_id} registered: {client}")
            if not client:
                return await error_response(
                    error="invalid_request",
                    error_description=f"Client ID '{auth_request.client_id}' could not be registered",
                    attempt_load_client=False,
                )

        # Validate redirect_uri
        try:
            redirect_uri = client.validate_redirect_uri(auth_request.redirect_uri)
        except InvalidRedirectUriError as validation_error:
            return await error_response(
                error="invalid_request",
                error_description=validation_error.message,
            )

        # Validate scope
        try:
            scopes = client.validate_scope(auth_request.scope)
        except InvalidScopeError as validation_error:
            return await error_response(
                error="invalid_scope",
                error_description=validation_error.message,
            )

        # Setup authorization parameters
        auth_params = AuthorizationParams(
            state=state,
            scopes=scopes,
            code_challenge=auth_request.code_challenge,
            redirect_uri=redirect_uri,
            redirect_uri_provided_explicitly=auth_request.redirect_uri is not None,
        )
        try:
            return RedirectResponse(
                url=await self.provider.authorize(client, auth_params),
                status_code=302,
                headers={"Cache-Control": "no-store"},
            )
        except AuthorizeError as e:
            return await error_response(
                error=e.error,
                error_description=e.error_description,
            )
        except Exception as validation_error:
            logger.exception(
                "Unexpected error in authorization_handler (GET)",
                exc_info=validation_error,
            )
            return await error_response(
                error="server_error", error_description="An unexpected error occurred"
            )

    async def handle_post(self, request: Request) -> Response:
        """Handle POST /authorize."""
        state = None
        redirect_uri = None
        client = None
        params = await request.form()

        async def error_response(
            error: AuthorizationErrorCode,
            error_description: str | None,
            attempt_load_client: bool = True,
        ):
            nonlocal client, redirect_uri, state
            if client is None and attempt_load_client:
                client_id = best_effort_extract_string("client_id", params)
                client = client_id and await self.provider.get_client(client_id)
            if redirect_uri is None and client:
                try:
                    # FormData is always not None, so just check key
                    if "redirect_uri" not in params:
                        raw_redirect_uri = None
                    else:
                        raw_redirect_uri = AnyHttpUrlModel.model_validate(
                            best_effort_extract_string("redirect_uri", params)
                        ).root
                    redirect_uri = client.validate_redirect_uri(raw_redirect_uri)
                except (ValidationError, InvalidRedirectUriError):
                    pass
            if state is None:
                state = best_effort_extract_string("state", params)
            error_resp = AuthorizationErrorResponse(
                error=error,
                error_description=error_description,
                state=state,
            )
            if redirect_uri and client:
                return RedirectResponse(
                    url=construct_redirect_uri(
                        str(redirect_uri), **error_resp.model_dump(exclude_none=True)
                    ),
                    status_code=302,
                    headers={"Cache-Control": "no-store"},
                )
            else:
                return PydanticJSONResponse(
                    status_code=400,
                    content=error_resp,
                    headers={"Cache-Control": "no-store"},
                )

        # Parse and validate request
        state = best_effort_extract_string("state", params)
        try:
            auth_request = AuthorizationRequest.model_validate(params)
            state = auth_request.state
        except ValidationError as validation_error:
            error: AuthorizationErrorCode = "invalid_request"
            for e in validation_error.errors():
                if e["loc"] == ("response_type",) and e["type"] == "literal_error":
                    error = "unsupported_response_type"
                    break
            return await error_response(
                error, stringify_pydantic_error(validation_error)
            )

        # Get client information
        client = await self.provider.get_client(auth_request.client_id)
        if not client:
            return await error_response(
                error="invalid_request",
                error_description=f"Client ID '{auth_request.client_id}' not found",
                attempt_load_client=False,
            )

        # Validate redirect_uri
        try:
            redirect_uri = client.validate_redirect_uri(auth_request.redirect_uri)
        except InvalidRedirectUriError as validation_error:
            return await error_response(
                error="invalid_request",
                error_description=validation_error.message,
            )

        # Validate scope
        try:
            scopes = client.validate_scope(auth_request.scope)
        except InvalidScopeError as validation_error:
            return await error_response(
                error="invalid_scope",
                error_description=validation_error.message,
            )

        # Setup authorization parameters
        auth_params = AuthorizationParams(
            state=state,
            scopes=scopes,
            code_challenge=auth_request.code_challenge,
            redirect_uri=redirect_uri,
            redirect_uri_provided_explicitly=auth_request.redirect_uri is not None,
        )
        try:
            return RedirectResponse(
                url=await self.provider.authorize(client, auth_params),
                status_code=302,
                headers={"Cache-Control": "no-store"},
            )
        except AuthorizeError as e:
            return await error_response(
                error=e.error,
                error_description=e.error_description,
            )
        except Exception as validation_error:
            logger.exception(
                "Unexpected error in authorization_handler (POST)",
                exc_info=validation_error,
            )
            return await error_response(
                error="server_error", error_description="An unexpected error occurred"
            )
