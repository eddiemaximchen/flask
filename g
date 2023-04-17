g就當作執行期間 全域的list 

如果每個route都需要同一個變數值 那就可以在 before request 時先存在 g 裡

from flask import g

@app.before_request
def get_name():
  g.name=request.args.get('name') #g
