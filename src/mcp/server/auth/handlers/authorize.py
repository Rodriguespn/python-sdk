import logging
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import AnyHttpUrl, AnyUrl, BaseModel, Field, RootModel, ValidationError
from starlette.datastructures import FormData, QueryParams
from starlette.requests import Request  # noqa: F811

from starlette.responses import RedirectResponse, Response
from starlette.templating import Jinja2Templates
import base64
import json
from http.cookies import SimpleCookie
import os

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
from mcp.server.auth.settings import ClientRegistrationOptions
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







from starlette.requests import Request
def is_client_already_approved(request: Request, client_id: str, cookie_secret: str = "") -> bool:
    cookie = request.cookies.get("approved_clients")
    if not cookie:
        return False
    try:
        approved = json.loads(cookie)
        return client_id in approved
    except Exception:
        return False


def update_approved_clients_cookie(response: Response, client_id: str):
    # Get current approved clients from cookie
    cookie = response.headers.get("set-cookie")
    approved = []
    if cookie:
        try:
            c = SimpleCookie()
            c.load(cookie)
            if "approved_clients" in c:
                approved = json.loads(c["approved_clients"].value)
        except Exception:
            approved = []
    if client_id not in approved:
        approved.append(client_id)
    # Set cookie
    response.set_cookie(
        key="approved_clients",
        value=json.dumps(approved),
        httponly=True,
        max_age=60 * 60 * 24 * 30,  # 30 days
        path="/"
    )


@dataclass
class AuthorizationHandler:
    provider: OAuthAuthorizationServerProvider[Any, Any, Any]
    client_registration_options: ClientRegistrationOptions = None

    async def handle_get(self, request: Request) -> Response:
        """Handle GET /authorize. Register client if not found. Render approval dialog if not approved."""
        params = request.query_params
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
            return PydanticJSONResponse(
                status_code=400,
                content=AuthorizationErrorResponse(
                    error=error,
                    error_description=stringify_pydantic_error(validation_error),
                    state=state,
                ),
                headers={"Cache-Control": "no-store"},
            )

        # Try to get client
        client = await self.provider.get_client(auth_request.client_id)
        if not client:
            from mcp.server.auth.handlers.register import build_and_register_client
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
            registration_options = self.client_registration_options
            try:
                await build_and_register_client(
                    self.provider,
                    client_metadata,
                    registration_options,
                    client_id=auth_request.client_id,
                )
            except Exception as e:
                return PydanticJSONResponse(
                    status_code=400,
                    content=AuthorizationErrorResponse(
                        error="invalid_request",
                        error_description=f"Client registration failed: {e}",
                        state=state,
                    ),
                    headers={"Cache-Control": "no-store"},
                )
            client = await self.provider.get_client(auth_request.client_id)
            if not client:
                return PydanticJSONResponse(
                    status_code=400,
                    content=AuthorizationErrorResponse(
                        error="invalid_request",
                        error_description=f"Client ID '{auth_request.client_id}' could not be registered",
                        state=state,
                    ),
                    headers={"Cache-Control": "no-store"},
                )

        # Validate response_type
        if auth_request.response_type not in client.response_types:
            return PydanticJSONResponse(
                status_code=400,
                content={"code": "invalid_request", "error": "invalid response type"},
            )

        # Validate redirect_uri
        if not auth_request.redirect_uri or auth_request.redirect_uri not in client.redirect_uris:
            return PydanticJSONResponse(
                status_code=400,
                content={"code": "invalid_request", "error": "invalid redirect uri"},
            )

        # Check if already approved
        # Use client.client_id instead of client.id
        if is_client_already_approved(request, client.client_id):
            # Upstream: redirect to provider.authorize
            # Here, encode the request params as state and redirect
            state_b64 = base64.b64encode(json.dumps(dict(params)).encode()).decode()
            # Simulate upstreamAuth: pass state_b64 as state
            scopes = client.validate_scope(auth_request.scope)
            auth_params = AuthorizationParams(
                state=state_b64,
                scopes=scopes,
                code_challenge=auth_request.code_challenge,
                redirect_uri=auth_request.redirect_uri,
                redirect_uri_provided_explicitly=bool(auth_request.redirect_uri),
            )
            try:
                return RedirectResponse(
                    url=await self.provider.authorize(client, auth_params),
                    status_code=302,
                    headers={"Cache-Control": "no-store"},
                )
            except Exception as e:
                return PydanticJSONResponse(
                    status_code=400,
                    content=AuthorizationErrorResponse(
                        error="server_error",
                        error_description=str(e),
                        state=state,
                    ),
                    headers={"Cache-Control": "no-store"},
                )

        # Not approved: render approval dialog via provider
        state_b64 = base64.b64encode(json.dumps(dict(params)).encode()).decode()
        return await self.provider.render_approval_dialog(request, client, state_b64)

    async def handle_post(self, request: Request) -> Response:
        """Handle POST /authorize."""
        state = None
        redirect_uri = None
        client = None
        params = await request.form()

        # If only 'state' is present, decode it and use as params
        if (
            set(params.keys()) == {"state"}
            or ("state" in params and not any(k in params for k in ["client_id", "response_type", "code_challenge"]))
        ):
            try:
                decoded = base64.b64decode(params["state"]).decode()
                decoded_params = json.loads(decoded)
                # Merge state from POST (in case it's changed)
                decoded_params["state"] = params["state"]
                params = decoded_params
            except Exception as e:
                return PydanticJSONResponse(
                    status_code=400,
                    content=AuthorizationErrorResponse(
                        error="invalid_request",
                        error_description=f"Failed to decode state: {e}",
                        state=params.get("state"),
                    ),
                    headers={"Cache-Control": "no-store"},
                )

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

        # Mark client as approved in cookie
        response = RedirectResponse(
            url=await self.provider.authorize(client, AuthorizationParams(
                state=state,
                scopes=scopes,
                code_challenge=auth_request.code_challenge,
                redirect_uri=redirect_uri,
                redirect_uri_provided_explicitly=auth_request.redirect_uri is not None,
            )),
            status_code=302,
            headers={"Cache-Control": "no-store"},
        )
        update_approved_clients_cookie(response, client.client_id)
        return response
