import requests

url = "http://www.wycdc.cn/admin/admin_checklogin.asp?action=adminlogin"
data = {"name" : "admin", "password" : "password", "GetCode" : "1234"}

res = requests.post(url, data=data)
# print (res.text)