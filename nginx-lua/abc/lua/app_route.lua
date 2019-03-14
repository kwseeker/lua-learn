local request_uri = ngx.var.request_uri
ngx.log(ngx.INFO, string.format("req url:%s\n", request_uri))
if string.find(request_uri, '/uc/') then
        res = '10.1.5.121:38081'
elseif string.find(request_uri, '/biz/') then
        res = '10.1.5.121:38080'
elseif string.find(request_uri, '/upgrade/') then
        res = '10.1.5.121:38082'
else
        res=''
end
ngx.log(ngx.INFO, string.format("res:%s\n", res))
ngx.var.backend = res