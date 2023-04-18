# from urlparse import urlparse, urljoin  # python3需要从urllib.parse导入
from urllib.parse import urlparse, urljoin

from flask import request, Flask, url_for, redirect


app = Flask(__name__)


@app.route('/bar')
def bar():

    print("request.full_path:", request.full_path)

    return '<h1>Bar page</h1><a href="%s">Do something and redirect </a>' % url_for('do_something', next=request.full_path)


@app.route('/do_something_and_redirect')
def do_something():

    return redirect_back()

def is_safe_url(target):

    print("request.host_url:", request.host_url)

    ref_url = urlparse(request.host_url)

    print("ref_url:", ref_url)

    print("target:", target)

    test_url = urlparse(urljoin(request.host_url, target))

    print("test_url:", test_url)

    print("ref_url.netloc:", ref_url.netloc)

    print("test_url.netloc:", test_url.netloc)

    print("test_url.scheme:", test_url.scheme)

    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


def redirect_back(default='hello', **kwargs):

    for target in request.args.get('next'), request.referrer:

        if target:

            if is_safe_url(target):

                return redirect(target)

    return redirect(url_for(default, **kwargs))


if __name__ == '__main__':

    app.run(debug=True)




