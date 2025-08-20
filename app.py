from flask import Flask, render_template, request, redirect, url_for, session, flash
from openshift.dynamic import DynamicClient
from kubernetes import config
import os
from dotenv import load_dotenv
from datetime import timedelta
import requests

# Load config from config.env
load_dotenv('config.env')

OPENSHIFT_API_URL = os.environ.get('OPENSHIFT_API_URL', 'https://api.crc.testing:6443')

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        token = request.form['token']
        api_url = os.environ.get('OPENSHIFT_API_URL', 'https://api.crc.testing:6443')
        try:
            from kubernetes import client as k8s_client_mod
            configuration = k8s_client_mod.Configuration()
            configuration.host = api_url
            configuration.verify_ssl = False
            configuration.api_key = {"authorization": "Bearer " + token}
            api_instance = k8s_client_mod.CoreV1Api(k8s_client_mod.ApiClient(configuration))
            api_instance.get_api_resources()  # Will raise if token is invalid
            session['token'] = token
            session['username'] = 'Authenticated User'
            session.permanent = True
            return redirect(url_for('welcome'))
        except Exception:
            error_message = 'Please use a valid token.'
            return render_template('login_error.html', error_message=error_message)
    return render_template('login.html', api_url=os.environ.get('OPENSHIFT_API_URL', 'https://api.crc.testing:6443'))

@app.route('/welcome')
def welcome():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('welcome.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    resp = redirect(url_for('login'))
    resp.set_cookie('session', '', expires=0)
    return resp

@app.route('/nodes')
def nodes():
    if 'username' not in session:
        return redirect(url_for('login'))
    api_urls = os.environ.get('OPENSHIFT_API_URLS', '').split(',')
    token = session.get('token')
    results = []
    total_nodes = 0
    from kubernetes import client as k8s_client_mod
    permission_denied = False
    for url in api_urls:
        url = url.strip()
        try:
            configuration = k8s_client_mod.Configuration()
            configuration.host = url
            configuration.verify_ssl = False
            configuration.api_key = {"authorization": "Bearer " + token}
            api_instance = k8s_client_mod.CoreV1Api(k8s_client_mod.ApiClient(configuration))
            node_list = api_instance.list_node()
            node_count = len(node_list.items)
        except k8s_client_mod.exceptions.ApiException as e:
            if e.status == 403:
                permission_denied = True
                break
            else:
                node_count = "Error"
        except Exception:
            node_count = "Error"
        results.append({'api_url': url, 'node_count': node_count})
        if isinstance(node_count, int):
            total_nodes += node_count
    if permission_denied:
        return render_template('permission_error.html')
    return render_template('nodes.html', clusters=results, total_nodes=total_nodes)

if __name__ == '__main__':
    # For development only: run with self-signed certs
    context = ('./cert.pem', './key.pem')  # Path to your certificate and key
    app.run(host='0.0.0.0', port=5000,debug=True, ssl_context=context)
