local request_method = ngx.var.request_method

if "GET" == request_method then
    args = ngx.req.get_uri_args()
elseif "POST" == request_method then
    ngx.req.read_body()
    args = ngx.req.get_post_args()
end
local arg_obj = cjson.decode(args)  


function _reqData.new(self, reqdata_entity)
	local reqdata_entity = reqdata_entity or {}
	setmetatable(reqdata_entity, self)
	self.__index = self
	return reqdata_entity
end

return _reqnManager