-- auth_token.lua
-- 请求验证模块
local cjson = require "cjson"
local redis = require "redis_mcredis"
local red = redis:new()
local _reqnManager = {}
_reqnManager._VERSION = '1.0.0'
_reqnManager._AUTHOR = 'zqz'

-- 判断Redis值是否为空
local function is_redis_null( res )
    if type(res) == "table" then
        for k,v in pairs(res) do
            if v ~= ngx.null then
                return false
            end
        end
        return true
    elseif res == ngx.null then
        return true
    elseif res == nil then
        return true
    end
    return false
end

function _reqnManager.check_auth_token(self,user_id)
	local redis_json, err = red:get("user:loginmt:"..user_id)
	if is_redis_null(redis_json) then
		ngx.log(ngx.INFO, string.format("user_id:%s, 找不到对应数据", user_id))
		return nil
	end
	return cjson.decode(redis_json)
end


function _reqnManager.get_req_json()
	--local request_method = ngx.var.request_method
	--获取参数的值
	--if "GET" == request_method then
	--	args = ngx.req.get_uri_args()
	--elseif "POST" == request_method then
	--	ngx.req.read_body()
		--args = ngx.req.get_post_args()
	--	 args = ngx.req.get_body_data()
	--	ngx.log(ngx.INFO, string.format("ngx.req.get_body_data****** :%s\n",args))
	--	if args==nil then
	--		ngx.log(ngx.INFO, string.format("ngx.req.get_post_args****** :%s\n",ngx.req.get_post_args()))
	---		args = ngx.req.get_post_args()
	--	end
	--end
    local args =init_form_args()
    -- if type(args) == "table" then
    --     return args
    -- elseif type(args) == "string" then
    --     return cjson.decode(args) 
    -- end
    --ngx.log(ngx.INFO, string.format("请求接口传入参数 :%s\n",cjson.encode(args)))
    return cjson.decode(args) 
end

-- 验证入口，验证请求合法性
function _reqnManager.check_requst_validity(self,req_json)
	--local headers = ngx.req.get_headers()
	--ngx.log(ngx.INFO, string.format("请求接口传入headers :%s\n", cjson.encode(headers)))
	--local req_json = get_req_json()
	if req_json==nil then 
		return error_output()
    end
	local req_param = req_json.req_param
	if req_param==nil then 
		return error_output()
    end
	local pub_info = req_param.pub_info
	if pub_info==nil then 
		return error_output()
    end
	local user_id = pub_info.user_id
	if user_id==nil or req_time=='' then 
		return error_output()
    end
	local req_time = pub_info.req_time
	if req_time==nil or req_time=='' then 
		return error_output("9004","无效的请求时间！");
    end
	local req_time_format = getNewDateFormat(req_time)
	local cur_time = os.time()
	ngx.log(ngx.INFO, string.format("req_time_format****** :%s\n",req_time_format))
	ngx.log(ngx.INFO, string.format("os.time()-req_time_format****** :%s\t,%s\n",os.date("%Y-%m-%d %H:%M:%S",cur_time),cur_time-req_time_format))
	if math.abs(cur_time-req_time_format)>10*60 then
		return error_output("9004","您的手机时间不准，请设置后再试！")
	end
	
	local sign = pub_info.sign
	if sign==nil then 
		return error_output()
    end
	local req_src = pub_info.req_src
	if in_array(req_src) then
		return error_output("9001","无效的请求方来源")
	end
	local ver = pub_info.ver
	if ver==nil or ver ~='1.0' then 
		return error_output("9002","无效的接口版本号")
    end
	-- 验证Token合法性并返回User ID
	local redis_json = self:check_auth_token(user_id)
	if redis_json==nil then 
		return error_output("9003","无效的用户令牌")
    end
	ngx.log(ngx.INFO, string.format("end_time format before****** :%s\n",redis_json.end_time))
	local end_time = date_format(redis_json.end_time)
	ngx.log(ngx.INFO, string.format("end_time format after****** :%s\n",end_time))
	ngx.log(ngx.INFO, string.format("system current time :%s\n",cur_time))
	if end_time<cur_time then 
		ngx.log(ngx.INFO, string.format("************ :%s\n",9003))
		return error_output("9003","无效的用户令牌")
	end
	local mt = redis_json.mt
	ngx.log(ngx.INFO, string.format("redis cache mt with user_id :%s\t %s \n", mt,user_id))
	local signStr = user_id..req_time..mt
	ngx.log(ngx.INFO, string.format("user_id..req_time..mt signMd5 before :%s\n", signStr))
	local signMd5=ngx.md5(signStr)
	ngx.log(ngx.INFO, string.format("user_id..req_time..mt signMd5 after:%s\n", signMd5))
	ngx.log(ngx.INFO, string.format("sign ************:%s\n",sign))	
	if  signMd5 ~=sign then
		ngx.log(ngx.INFO, string.format("signMd5 ~=sign ************:%s\n",signMd5 ~=sign))	
		return error_output("9005","无效的签名")
	end
	return error_output("0000","成功")
end

function  in_array(req_src)
	local arr={["1"]="H5",["2"]="Android",["3"]="IOS",["4"]="运营平台"}
	 local is_false=true
	   for k, v in pairs(arr) do
			ngx.log(ngx.INFO, string.format("vvvvvvvv************:%s\t%s\t%s\n",v,k,req_src))	
		   if k ==req_src then
			  is_false = false
		   end
	   end
	return is_false
end

function error_output(codeStr,messageStr)
	if codeStr ==nil then
		codeStr="9998"
	end
	if messageStr ==nil then
		messageStr="无效的请求参数"
	end
	local _result = {
		rsp_param={
			pub_info={
				code=codeStr,
				message=messageStr,
				rsp_time=os.date("%Y%m%d%H%M%S",os.time())
			},
			page_info={},
			busi_info={}
		}
	}
	return _result, nil
end

function explode ( _str,seperator )
    local pos, arr = 0, {}
        for st, sp in function() return string.find( _str, seperator, pos, true ) end do
            table.insert( arr, string.sub( _str, pos, st-1 ) )
            pos = sp + 1
        end
    table.insert( arr, string.sub( _str, pos ) )
    return arr
end

function init_form_args()
	local args = {}
	local file_args = {}
	local is_have_file_param = false
    local receive_headers = ngx.req.get_headers()
    local request_method = ngx.var.request_method
    if "GET" == request_method then
        args = ngx.req.get_uri_args()
    elseif "POST" == request_method then
        ngx.req.read_body()
        --判断是否是multipart/form-data类型的表单
        ngx.log(ngx.INFO, string.format("请求content-type: %s\n", string.sub(receive_headers["content-type"],1,20)))
        if string.sub(receive_headers["content-type"],1,20) == "multipart/form-data;" then   
            is_have_file_param = true
            content_type = receive_headers["content-type"]
            ngx.log(ngx.INFO, string.format("请求content-type: %s\n", content_type))
            --body_data可是符合http协议的请求体，不是普通的字符串
            body_data = ngx.req.get_body_data()
            --ngx.log(ngx.INFO, string.format("请求 body: %s\n", body_data))
            --请求体的size大于nginx配置里的client_body_buffer_size，则会导致请求体被缓冲到磁盘临时文件里，client_body_buffer_size默认是8k或者16k
            if not body_data then   -- body 为空
                ngx.log(ngx.INFO, string.format("debug 1 ---------\n"))
                local datafile = ngx.req.get_body_file()
                if not datafile then
                    ngx.log(ngx.INFO, string.format("debug 2 ---------\n"))
                    error_code = 1
                    error_msg = "no request body found"
                else
                    ngx.log(ngx.INFO, string.format("debug 3 ---------\n"))
                    local fh, err = io.open(datafile, "r")
                    if not fh then
                        ngx.log(ngx.INFO, string.format("debug 4 ---------\n"))
                        error_code = 2
                        error_msg = "failed to open " .. tostring(datafile) .. "for reading: " .. tostring(err)
                    else
                        ngx.log(ngx.INFO, string.format("debug 5 ---------\n"))
                        fh:seek("set")
                        body_data = fh:read("*a")
                        fh:close()
                        if body_data == "" then
                            error_code = 3
                            error_msg = "request body is empty"
                        end
                    end
                end
            end

            local new_body_data = {}

            -- 确保取到请求体的数据
            if not error_code then
                ngx.log(ngx.INFO, string.format("debug 6 ---------\n"))
                local boundary = "--" .. string.sub(receive_headers["content-type"],31)
                local body_data_table = explode(tostring(body_data),boundary)
                local first_string = table.remove(body_data_table,1)
                local last_string = table.remove(body_data_table)
                for i,v in ipairs(body_data_table) do
                    local start_pos,end_pos,capture,capture2 = string.find(v,'Content%-Disposition: form%-data; name="(.+)"; filename="(.*)"')
                    ngx.log(ngx.INFO, string.format("debug 7 ---------\n"))
                    --普通参数
                    if not start_pos then
                        ngx.log(ngx.INFO, string.format("debug 8 ---------\n"))
                        local t = explode(v,"rnrn")
						ngx.log(ngx.INFO, string.format("file ttttttt:************:%s\n",cjson.encode(t)))	
						ngx.log(ngx.INFO, string.format("t[1]:************:%s\n",t[1]))	
						local s,e=string.find(t[1],"req_param")
						ngx.log(ngx.INFO, string.format("start pos ************:%s\n",s-2))	
                        local temp_param_value = string.sub(t[1],s-2,string.len(t[1]))
							ngx.log(ngx.INFO, string.format("temp_param_value:************:%s\n",temp_param_value))
                        args=temp_param_value
                    else
                    --文件类型的参数，capture是参数名称，capture2是文件名  
                        ngx.log(ngx.INFO, string.format("debug 9 ---------\n"))                          
                        file_args[capture] = capture2
                        table.insert(new_body_data,v)
                    end
                end
                table.insert(new_body_data,1,first_string)
                table.insert(new_body_data,last_string)
                --去掉app_key,app_secret等几个参数，把业务级别的参数传给内部的API
                body_data = table.concat(new_body_data,boundary)--body_data可是符合http协议的请求体，不是普通的字符串
            end
            args = "{}"
        else
            args = ngx.req.get_body_data()
        end
    end
	return args
end
 
function date_format(timeString)
    if type(timeString) ~= 'string' then 
		ngx.log('string2time: timeString is not a string') 
		return 0
	end
    local fun = string.gmatch(timeString,"%d+")
    local y = fun() or 0
    if y == 0 then error('timeString is a invalid time string') return 0 end
    local m = fun() or 0
    if m == 0 then error('timeString is a invalid time string') return 0 end
    local d = fun() or 0
    if d == 0 then error('timeString is a invalid time string') return 0 end
    local H = fun() or 0
    if H == 0 then error('timeString is a invalid time string') return 0 end
    local M = fun() or 0
    if M == 0 then error('timeString is a invalid time string') return 0 end
    local S = fun() or 0
    if S == 0 then error('timeString is a invalid time string') return 0 end
    return os.time({year=y, month=m, day=d, hour=H,min=M,sec=S})
end

function getNewDateFormat(srcDateTime)  
    --从日期字符串中截取出年月日时分秒  
    local Y = string.sub(srcDateTime,1,4)  
    local M = string.sub(srcDateTime,5,6)  
    local D = string.sub(srcDateTime,7,8)  
    local H = string.sub(srcDateTime,9,10)  
    local MM = string.sub(srcDateTime,11,12)  
    local SS = string.sub(srcDateTime,13,14)  
  
    --把日期时间字符串转换成对应的日期时间  
    local dt1 = os.time{year=Y, month=M, day=D, hour=H,min=MM,sec=SS}  
    return dt1;  
end 

function getNewDate(srcDateTime,interval ,dateUnit)  
    --从日期字符串中截取出年月日时分秒  
    local Y = string.sub(srcDateTime,1,4)  
    local M = string.sub(srcDateTime,5,6)  
    local D = string.sub(srcDateTime,7,8)  
    local H = string.sub(srcDateTime,9,10)  
    local MM = string.sub(srcDateTime,11,12)  
    local SS = string.sub(srcDateTime,13,14)  
  
    --把日期时间字符串转换成对应的日期时间  
    local dt1 = os.time{year=Y, month=M, day=D, hour=H,min=MM,sec=SS}  
  
    --根据时间单位和偏移量得到具体的偏移数据  
    local ofset=0  
  
    if dateUnit =='DAY' then  
        ofset = 60 *60 * 24 * interval  
  
    elseif dateUnit == 'HOUR' then  
        ofset = 60 *60 * interval  
          
	elseif dateUnit == 'MINUTE' then  
        ofset = 60 * interval  
  
    elseif dateUnit == 'SECOND' then  
        ofset = interval  
    end  
  
    --指定的时间+时间偏移量  
    local newTime = os.date("*t", dt1 + tonumber(ofset))  
    return newTime  
end  
 
function _reqnManager.new(self, req_entity)
	local req_entity = req_entity or {}
	setmetatable(req_entity, self)
	self.__index = self
	return req_entity
end

return _reqnManager