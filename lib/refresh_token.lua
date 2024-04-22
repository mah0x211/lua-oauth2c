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
local is_str = require('lauxhlib.is').str
local new_request = require('oauth2c.request')

--
-- https://datatracker.ietf.org/doc/html/rfc6749#section-6
-- 6.  Refreshing an Access Token
--
--  If the authorization server issued a refresh token to the client, the
--  client makes a refresh request to the token endpoint by adding the
--  following parameters using the "application/x-www-form-urlencoded"
--  format per Appendix B with a character encoding of UTF-8 in the HTTP
--  request entity-body:
--
--  grant_type
--        REQUIRED.  Value MUST be set to "refresh_token".
--
--  refresh_token
--        REQUIRED.  The refresh token issued to the client.
--
--  scope
--        OPTIONAL.  The scope of the access request as described by
--        Section 3.3.  The requested scope MUST NOT include any scope
--        not originally granted by the resource owner, and if omitted is
--        treated as equal to the scope originally granted by the
--        resource owner.
--
--  Because refresh tokens are typically long-lasting credentials used to
--  request additional access tokens, the refresh token is bound to the
--  client to which it was issued.  If the client type is confidential or
--  the client was issued client credentials (or assigned other
--  authentication requirements), the client MUST authenticate with the
--  authorization server as described in Section 3.2.1.
--
--  For example, the client makes the following HTTP request using
--  transport-layer security (with extra line breaks for display purposes
--  only):
--
--    POST /token HTTP/1.1
--    Host: server.example.com
--    Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
--    Content-Type: application/x-www-form-urlencoded
--
--    grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
--
--  The authorization server MUST:
--
--  o  require client authentication for confidential clients or for any
--     client that was issued client credentials (or with other
--     authentication requirements),
--
--  o  authenticate the client if client authentication is included and
--     ensure that the refresh token was issued to the authenticated
--     client, and
--
--  o  validate the refresh token.
--
--  If valid and authorized, the authorization server issues an access
--  token as described in Section 5.1.  If the request failed
--  verification or is invalid, the authorization server returns an error
--  response as described in Section 5.2.
--
--  The authorization server MAY issue a new refresh token, in which case
--  the client MUST discard the old refresh token and replace it with the
--  new refresh token.  The authorization server MAY revoke the old
--  refresh token after issuing a new refresh token to the client.  If a
--  new refresh token is issued, the refresh token scope MUST be
--  identical to that of the refresh token included by the client in the
--  request.
--
--- @class oauth2c.refresh_token.request.params : oauth2c.request.params
--- @field grant_type string @ REQUIRED. Value MUST be set to "refresh_token".
--- @field refresh_token string @ REQUIRED. The refresh token issued to the client.
--- @field scope string @ OPTIONAL. The scope of the access request as described by Section 3.3. The requested scope MUST NOT include any scope not originally granted by the resource owner, and if omitted is treated as equal to the scope originally granted by the resource owner.
--- @field client_id string @ REQUIRED. The client identifier as described in Section 2.2
--- @field client_secret string @ REQUIRED. The client secret as described in Section 2.3.1

--- @class oauth2c.refresh_token.request : oauth2c.request
--- @field uri string @ token endpoint URI
--- @field params oauth2c.refresh_token.request.params

--- create_refresh_token_request
--- @param uri string @ token endpoint URI
--- @param refresh_token string @ refresh token
--- @param scope string? @ OPTIONAL. The scope of the access request as described by Section 3.3. The requested scope MUST NOT include any scope not originally granted by the resource owner, and if omitted is treated as equal to the scope originally granted by the resource owner.
--- @param client_id? string @ REQUIRED. The client identifier as described in Section 2.2
--- @param client_secret? string @ REQUIRED. The client secret as described in Section 2.3.1
--- @return oauth2c.refresh_token.request req
local function create_request(uri, refresh_token, scope, client_id,
                              client_secret)
    assert(is_str(uri), 'uri must be string')
    assert(is_str(refresh_token), 'refresh_token must be string')
    assert(scope == nil or is_str(scope), 'scope must be string or nil')
    assert(client_id == nil or is_str(client_id),
           'client_id must be string or nil')
    assert(client_secret == nil or is_str(client_secret),
           'client_secret must be string or nil')

    return new_request(uri, {
        grant_type = 'refresh_token',
        refresh_token = refresh_token,
        scope = scope,
        client_id = client_id,
        client_secret = client_secret,
    })
end

return {
    request = create_request,
}
