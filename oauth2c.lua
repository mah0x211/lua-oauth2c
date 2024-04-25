--
-- Copyright (C) 2024-present Masatoshi Fukunaga
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
-- THE SOFTWARE.
--
local is = require('lauxhlib.is')
local fatalf = require('error').fatalf
local errorf = require('error').format
local create_authorization_request = require('oauth2c.authorization').request
local verify_authorization_response = require('oauth2c.authorization').response
local create_access_token_request = require('oauth2c.access_token').request
local verify_access_token_response = require('oauth2c.access_token').response
local create_refresh_token_request = require('oauth2c.refresh_token').request

--- @class oauth2c.params
--- @field client_id string
--- @field client_secret string
--- @field redirect_uri string
--- @field authz_uri string
--- @field token_uri string

-- https://tools.ietf.org/html/rfc6749#section-2.3.1
-- 2.3.1.  Client Password
--  Clients in possession of a client password MAY use the HTTP Basic
--  authentication scheme as defined in [RFC2617] to authenticate with
--  the authorization server.  The client identifier is encoded using the
--  "application/x-www-form-urlencoded" encoding algorithm per
--  Appendix B, and the encoded value is used as the username; the client
--  password is encoded using the same algorithm and used as the
--  password.  The authorization server MUST support the HTTP Basic
--  authentication scheme for authenticating clients that were issued a
--  client password.
--
--  For example (with extra line breaks for display purposes only):
--
--    Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3
--
--  Alternatively, the authorization server MAY support including the
--  client credentials in the request-body using the following
--  parameters:
--
--  client_id
--        REQUIRED.  The client identifier issued to the client during
--        the registration process described by Section 2.2.
--
--  client_secret
--        REQUIRED.  The client secret.  The client MAY omit the
--        parameter if the client secret is an empty string.
--
--  Including the client credentials in the request-body using the two
--  parameters is NOT RECOMMENDED and SHOULD be limited to clients unable
--  to directly utilize the HTTP Basic authentication scheme (or other
--  password-based HTTP authentication schemes).  The parameters can only
--  be transmitted in the request-body and MUST NOT be included in the
--  request URI.
--
--  For example, a request to refresh an access token (Section 6) using
--  the body parameters (with extra line breaks for display purposes
--  only):
--
--    POST /token HTTP/1.1
--    Host: server.example.com
--    Content-Type: application/x-www-form-urlencoded
--
--    grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
--    &client_id=s6BhdRkqt3&client_secret=7Fjfp0ZBr1KtDRbnfVdmIw
--
--  The authorization server MUST require the use of TLS as described in
--  Section 1.6 when sending requests using password authentication.
--
--  Since this client authentication method involves a password, the
--  authorization server MUST protect any endpoint utilizing it against
--  brute force attacks.
--
-- constants
local PARAM_OPTIONS = {
    client_id = {
        req = true,
        type = 'str',
        errmsg = 'params.client_id must be string',
    },
    client_secret = {
        req = true,
        type = 'str',
        errmsg = 'params.client_secret must be string',
    },
    authz_uri = {
        req = true,
        type = 'str',
        errmsg = 'params.authz_uri must be string',
    },
    token_uri = {
        req = true,
        type = 'str',
        errmsg = 'params.token_uri must be string',
    },
    redirect_uri = {
        type = 'str',
        errmsg = 'params.redirect_uri must be string',
    },
}

--- @class oauth2c
--- @field params oauth2c.params
--- @field code string
--- @field tokens oauth2c.tokens
local OAuth2 = {}

--- init
--- @param params oauth2c.params
--- @return oauth2c
function OAuth2:init(params)
    assert(is.table(params), 'params must be table')

    local tbl = {}
    for k, def in pairs(PARAM_OPTIONS) do
        local v = params[k]
        if v ~= nil then
            if not is[def.type](v) then
                -- invalid data type
                fatalf(2, def.errmsg)
            end
            tbl[k] = v
        elseif def.req then
            fatalf(2, 'params.%s is required', k)
        end
    end

    self.params = tbl
    self.code = ''
    return self
end

--- @class oauth2c.tokens
--- @field access_token string
--- @field refresh_token string
--- @field expires_in number
--- @field token_type string
--- @field scope string

local TOKEN_OPTIONS = {
    access_token = {
        req = true,
        type = 'str',
        errmsg = 'access_token must be string',
    },
    token_type = {
        req = true,
        type = 'str',
        errmsg = 'token_type must be string',
    },
    expires_in = {
        type = 'uint',
        errmsg = 'expires_in must be unsigned integer',
    },
    refresh_token = {
        type = 'str',
        errmsg = 'refresh_token must be string',
    },
    scope = {
        type = 'str',
        errmsg = 'scope must be string',
    },
}

--- set_tokens
--- @param tokens oauth2c.tokens
--- @return boolean ok
--- @return any err
function OAuth2:set_tokens(tokens)
    assert(is.table(tokens), 'tokens must be table')

    local tbl = {}
    for k, def in pairs(TOKEN_OPTIONS) do
        local v = tokens[k]
        if v ~= nil then
            if not is[def.type](v) then
                -- invalid data type
                return false, errorf(def.errmsg)
            end
            tbl[k] = v
        elseif def.req then
            return false, errorf('%s is required', k)
        end
    end
    self.tokens = tbl
    return true
end

--- get_tokens
--- @return oauth2c.tokens?
function OAuth2:get_tokens()
    local tokens = self.tokens
    return tokens and {
        access_token = tokens.access_token,
        token_type = tokens.token_type,
        expires_in = tokens.expires_in,
        refresh_token = tokens.refresh_token,
        scope = tokens.scope,
    } or nil
end

--- create_authorization_header
--- @return string
function OAuth2:create_authorization_header()
    local tokens = self.tokens
    return tokens and (tokens.token_type .. ' ' .. tokens.access_token) or ''
end

--- authorization_request
--- @param scope? string
--- @return oauth2c.authorization.request req
function OAuth2:create_authorization_request(scope)
    return create_authorization_request(self.params.authz_uri,
                                        self.params.client_id,
                                        self.params.redirect_uri, scope)
end

--- verify_authorization_response_query
--- @param state string
--- @param query table|string
--- @return oauth2c.authorization.response|oauth2c.error_response? res
--- @return any err
function OAuth2:verify_authorization_response_query(state, query)
    local res, err = verify_authorization_response(state, query)
    if not res then
        return nil, err
    elseif not res.error then
        -- update code
        self.code = res.code
    end
    return res
end

--- create_access_token_request
--- @return oauth2c.access_token.request? req
--- @return any err
function OAuth2:create_access_token_request()
    if self.code == '' then
        return nil, errorf(
                   'you must call verify_authorization_response_query() to set the authorization code before calling access_token_request()')
    end

    return create_access_token_request(self.params.token_uri, self.code,
                                       self.params.redirect_uri,
                                       self.params.client_id,
                                       self.params.client_secret)
end

--- verify_access_token_response
--- @param response table|string
--- @return oauth2c.access_token.response|oauth2c.error_response? res
--- @return any err
function OAuth2:verify_access_token_response(response)
    local res, err = verify_access_token_response(response)
    if not res then
        return nil, err
    elseif not res.error then
        -- update tokens
        local ok
        ok, err = self:set_tokens(res)
        if not ok then
            return nil, err
        end
    end
    return res
end

--- create_refresh_token_request
--- @return oauth2c.refresh_token.request req
--- @return any err
function OAuth2:create_refresh_token_request()
    if not self.tokens or not self.tokens.refresh_token then
        return nil, errorf(
                   'you must call set_tokens() or verify_access_token_response() to set the refresh token before calling refresh_token_request()')
    end

    return create_refresh_token_request(self.params.token_uri,
                                        self.tokens.refresh_token,
                                        self.tokens.scope,
                                        self.params.client_id,
                                        self.params.client_secret)
end

-- http://tools.ietf.org/html/rfc6749#section-5.2
-- 5.2.  Error Response
--
--  The authorization server responds with an HTTP 400 (Bad Request)
--  status code (unless specified otherwise) and includes the following
--  parameters with the response:
--
--  error
--        REQUIRED.  A single ASCII [USASCII] error code from the
--        following:
--
--        invalid_request
--              The request is missing a required parameter, includes an
--              unsupported parameter value (other than grant type),
--              repeats a parameter, includes multiple credentials,
--              utilizes more than one mechanism for authenticating the
--              client, or is otherwise malformed.
--
--        invalid_client
--              Client authentication failed (e.g., unknown client, no
--              client authentication included, or unsupported
--              authentication method).  The authorization server MAY
--              return an HTTP 401 (Unauthorized) status code to indicate
--              which HTTP authentication schemes are supported.  If the
--              client attempted to authenticate via the "Authorization"
--              request header field, the authorization server MUST
--              respond with an HTTP 401 (Unauthorized) status code and
--              include the "WWW-Authenticate" response header field
--              matching the authentication scheme used by the client.
--
--        invalid_grant
--              The provided authorization grant (e.g., authorization
--              code, resource owner credentials) or refresh token is
--              invalid, expired, revoked, does not match the redirection
--              URI used in the authorization request, or was issued to
--              another client.
--
--        unauthorized_client
--              The authenticated client is not authorized to use this
--              authorization grant type.
--
--        unsupported_grant_type
--              The authorization grant type is not supported by the
--              authorization server.
--
--        invalid_scope
--              The requested scope is invalid, unknown, malformed, or
--              exceeds the scope granted by the resource owner.
--
--        Values for the "error" parameter MUST NOT include characters
--        outside the set %x20-21 / %x23-5B / %x5D-7E.
--
--  error_description
--        OPTIONAL.  Human-readable ASCII [USASCII] text providing
--        additional information, used to assist the client developer in
--        understanding the error that occurred.
--        Values for the "error_description" parameter MUST NOT include
--        characters outside the set %x20-21 / %x23-5B / %x5D-7E.
--
--  error_uri
--        OPTIONAL.  A URI identifying a human-readable web page with
--        information about the error, used to provide the client
--        developer with additional information about the error.
--        Values for the "error_uri" parameter MUST conform to the
--        URI-reference syntax and thus MUST NOT include characters
--        outside the set %x21 / %x23-5B / %x5D-7E.
--
--  The parameters are included in the entity-body of the HTTP response
--  using the "application/json" media type as defined by [RFC4627].  The
--  parameters are serialized into a JSON structure by adding each
--  parameter at the highest structure level.  Parameter names and string
--  values are included as JSON strings.  Numerical values are included
--  as JSON numbers.  The order of parameters does not matter and can
--  vary.
--
--  For example:
--
--    HTTP/1.1 400 Bad Request
--    Content-Type: application/json;charset=UTF-8
--    Cache-Control: no-store
--    Pragma: no-cache
--
--    {
--      "error":"invalid_request"
--    }
--
--- @class oauth2c.error_response
--- @field error string A single ASCII error code from the following: invalid_request, invalid_client, invalid_grant, unauthorized_client, unsupported_grant_type, invalid_scope.
--- @field error_description string? Human-readable ASCII text providing additional information.
--- @field error_uri string? A URI identifying a human-readable web page with information about the error.

OAuth2 = require('metamodule').new(OAuth2)

return OAuth2
