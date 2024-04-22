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
local is_table = require('lauxhlib.is').table
local errorf = require('error').format
local encode = require('form.urlencoded').encode
local encode_json = require('yyjson').encode

--- @class oauth2c.request.params
--- @field client_id string @ REQUIRED. The client identifier as described in Section 2.2

--- @class oauth2c.request
--- @field uri string
--- @field params oauth2c.request.params
local Request = {}

--- init
--- @param uri string
--- @param params oauth2c.request.params
function Request:init(uri, params)
    assert(is_str(uri), 'uri must be string')
    assert(is_table(params), 'params must be table')
    self.uri = uri
    self.params = params
    return self
end

--- encode
--- @return string? encoded_uri
function Request:encode_uri()
    return self.uri .. '?' .. self:encode_params()
end

--- encode_params
--- @return string? encoded_params
function Request:encode_params()
    return encode(self.params)
end

--- encode_params_json
--- @return string? json_encoded_params
--- @return any err
function Request:encode_params_json()
    local params, err = encode_json(self.params)
    if not params then
        return nil, errorf('failed to encode request parameters as JSON:', err)
    end
    return params
end

Request = require('metamodule').new(Request)
return Request
