local cjson = require "cjson"
local auth_req_islegal = require "auth_req_islegal"
-- 检查是否合法的请求头
--local auth_req_headers = require "auth_req_headers"
--local headerManager = auth_req_headers:new()

local reqAuthManager = auth_req_islegal:new()
local req_json=reqAuthManager:get_req_json()	-- table类型 DONE: 传图片时会报 calling 'get_req_json' on bad self (string expected, got table) ,因为接口不能同时返回两种不同类型的结果
-- TODO：不直接跳过，而是添加校验信息
if next(req_json) == nil then
	ngx.log(ngx.INFO, string.format("直接跳过网关检查\n"))
	return ngx.exec("@auth_success")
end
local req_url = ngx.var.uri
ngx.log(ngx.INFO, string.format("req url:%s\t,req param:%s\n", req_url, cjson.encode(req_json)))
--local is_has_token = true

-- https://github.com/openresty/lua-nginx-module#ngxrematch
-- 匹配下面url的直接通过网关（即网关不拦截）
if ngx.re.match(req_url,"(/uc/autopresign).*$|(/uc/smspresign).*$|(/uc/smsdecrypt).*$|(/uc/tokenvalidate).*$|(/uc/mtvalidate).*$|(/upgrade/queryversion).*$|(/biz/mmcallback).*$") then
	ngx.log(ngx.INFO, string.format("req url pass :%s\n", req_url))
	return ngx.exec("@auth_success")
end

--local headerResult = headerManager:check_req_headers(is_has_token)
--if not headerResult then
	--ngx.log(ngx.INFO, "请求头不合法")
	--ngx.exit(403)
--end

-- 其余请求都要经过网关检查
ngx.log(ngx.INFO, string.format("req url filter :%s\n", req_url))

local checkResult, err = reqAuthManager:check_requst_validity(req_json)
ngx.log(ngx.INFO, string.format("checkResult ************:%s\n",cjson.encode(checkResult)))	
-- 处理验证结果
local switch = {
	["9001"] = function(response)
				-- Request Error The Token Is Timeout
				ngx.say(cjson.encode(response))
				ngx.exit(ngx.HTTP_OK)
			end,
	["9002"] = function(response)
				-- Request Error The Token Is Timeout
				ngx.say(cjson.encode(response))
				ngx.exit(ngx.HTTP_OK)
			end,
	["9003"] = function(response)
				-- Request Error The Token Is Timeout
				ngx.say(cjson.encode(response))
				ngx.exit(ngx.HTTP_OK)
			end,
	["9004"] = function(response)
				-- Request Error The Token Is Timeout
				ngx.say(cjson.encode(response))
				ngx.exit(ngx.HTTP_OK)
			end,
	["9005"] = function(response)
				-- Request Error The Token Is Timeout
				ngx.say(cjson.encode(response))
				ngx.exit(ngx.HTTP_OK)
			end,
	["1101"] = function(response)
				-- Request Error The Token Is Timeout
				ngx.say(cjson.encode(response))
				ngx.exit(ngx.HTTP_OK)
			end,
	["9998"] = function(response)
				-- Request Error The Token Is Timeout
				ngx.say(cjson.encode(response))
				ngx.exit(ngx.HTTP_OK)
			end
}
local s_case = switch[checkResult.rsp_param.pub_info.code]

if (s_case) then
	s_case(checkResult)
else
	-- for case default, success
	return ngx.exec("@auth_success")
end