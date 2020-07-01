from flask import Flask, jsonify, render_template, send_file, request, send_from_directory, redirect, url_for
from flask_swagger_ui import get_swaggerui_blueprint
from subprocess import call
from werkzeug.utils import secure_filename
from functools import wraps
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, create_refresh_token,
    get_jwt_identity, verify_jwt_in_request, jwt_refresh_token_required, get_raw_jwt
)
import waitress, os, uuid, glob, json, base64, zipfile, io, re, shutil, tempfile, subprocess, datetime
from logging.config import dictConfig

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

def get_file_as_string(path_file):
    f = None
    content = None
    try:
        f = open(path_file, "r")
        content = f.read()
    except Exception as ex:
        app.logger.error(str(ex))
    finally:
        if f is not None:
            f.close()
    return content

def generate_security_swagger_specification():
    if ENABLE_SECURITY_LOGIN:
        login_endpoint = get_file_as_string("{}/swagger/security_endpoints/login_endpoint.json".format(STATIC_CONTENT))
        logout_endpoint = get_file_as_string("{}/swagger/security_endpoints/logout_endpoint.json".format(STATIC_CONTENT))
        refresh_endpoint = get_file_as_string("{}/swagger/security_endpoints/refresh_endpoint.json".format(STATIC_CONTENT))
        try:
            with open("{}/swagger/swagger.json".format(STATIC_CONTENT)) as json_file:
                data = json.load(json_file)
                security_schemes = { "bearerAuth": { "type":"http", "scheme":"bearer", "bearerFormat": "JWT" } }
                login_scheme = { "type":"object", "properties":{ "username": { "type":"string" }, "password": { "type":"string" } } }
                security_endpoint = [ { "bearerAuth": [] } ]
                security_response = { "description": "UNAUTHORIZED", "schema": { "$ref":"#/components/schemas/response" } }

                data['paths']['/login'] = eval(login_endpoint)
                data['paths']['/logout'] = eval(logout_endpoint)
                data['paths']['/refresh'] = eval(refresh_endpoint)

                data['paths']['/latest-report']['get']['security'] = security_endpoint
                data['paths']['/latest-report']['get']['responses']['401'] = security_response

                data['paths']['/send-results']['post']['security'] = security_endpoint
                data['paths']['/send-results']['post']['responses']['401'] = security_response

                data['paths']['/generate-report']['get']['security'] = security_endpoint
                data['paths']['/generate-report']['get']['responses']['401'] = security_response

                data['paths']['/clean-results']['get']['security'] = security_endpoint
                data['paths']['/clean-results']['get']['responses']['401'] = security_response

                data['paths']['/emailable-report/render']['get']['security'] = security_endpoint
                data['paths']['/emailable-report/render']['get']['responses']['401'] = security_response

                data['paths']['/clean-history']['get']['security'] = security_endpoint
                data['paths']['/clean-history']['get']['responses']['401'] = security_response

                data['paths']['/emailable-report/export']['get']['security'] = security_endpoint
                data['paths']['/emailable-report/export']['get']['responses']['401'] = security_response

                data['paths']['/report/export']['get']['security'] = security_endpoint
                data['paths']['/report/export']['get']['responses']['401'] = security_response

                data['paths']['/projects']['post']['security'] = security_endpoint
                data['paths']['/projects']['post']['responses']['401'] = security_response

                data['paths']['/projects']['get']['security'] = security_endpoint
                data['paths']['/projects']['get']['responses']['401'] = security_response

                data['paths']['/projects/{id}']['delete']['security'] = security_endpoint
                data['paths']['/projects/{id}']['delete']['responses']['401'] = security_response

                data['paths']['/projects/{id}']['get']['security'] = security_endpoint
                data['paths']['/projects/{id}']['get']['responses']['401'] = security_response

                data['paths']['/projects/{id}/reports/{path}']['get']['security'] = security_endpoint
                data['paths']['/projects/{id}/reports/{path}']['get']['responses']['401'] = security_response

                data['components']['securitySchemes'] = security_schemes
                data['components']['schemas']['login'] = login_scheme

            with open("{}/swagger/swagger_security.json".format(STATIC_CONTENT), 'w') as outfile:
                json.dump(data, outfile)
        except Exception as ex:
            app.logger.error(str(ex))

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.urandom(16)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

DEV_MODE = 0
HOST = '0.0.0.0'
PORT = os.environ['PORT']
THREADS = 7
URL_SCHEME = 'http'
ENABLE_SECURITY_LOGIN = False
SECURITY_USER = None
SECURITY_PASS = None

GENERATE_REPORT_PROCESS = '{}/generateAllureReport.sh'.format(os.environ['ROOT'])
KEEP_HISTORY_PROCESS = '{}/keepAllureHistory.sh'.format(os.environ['ROOT'])
CLEAN_HISTORY_PROCESS = '{}/cleanAllureHistory.sh'.format(os.environ['ROOT'])
CLEAN_RESULTS_PROCESS = '{}/cleanAllureResults.sh'.format(os.environ['ROOT'])
RENDER_EMAIL_REPORT_PROCESS = '{}/renderEmailableReport.sh'.format(os.environ['ROOT'])
ALLURE_VERSION = os.environ['ALLURE_VERSION']
STATIC_CONTENT = os.environ['STATIC_CONTENT']
PROJECTS_DIRECTORY = os.environ['STATIC_CONTENT_PROJECTS']
EMAILABLE_REPORT_FILE_NAME = os.environ['EMAILABLE_REPORT_FILE_NAME']
ORIGIN='api'

REPORT_INDEX_FILE = 'index.html'
DEFAULT_TEMPLATE = 'default.html'
EMAILABLE_REPORT_CSS = "https://stackpath.bootstrapcdn.com/bootswatch/4.3.1/cosmo/bootstrap.css"
EMAILABLE_REPORT_TITLE = "Emailable Report"
API_RESPONSE_LESS_VERBOSE = 0

if "EMAILABLE_REPORT_CSS_CDN" in os.environ:
    EMAILABLE_REPORT_CSS = os.environ['EMAILABLE_REPORT_CSS_CDN']
    app.logger.info('Overriding CSS for Emailable Report. EMAILABLE_REPORT_CSS_CDN={}'.format(EMAILABLE_REPORT_CSS))

if "EMAILABLE_REPORT_TITLE" in os.environ:
    EMAILABLE_REPORT_TITLE = os.environ['EMAILABLE_REPORT_TITLE']
    app.logger.info('Overriding Title for Emailable Report. EMAILABLE_REPORT_TITLE={}'.format(EMAILABLE_REPORT_TITLE))

if "API_RESPONSE_LESS_VERBOSE" in os.environ:
    try:
        API_RESPONSE_LESS_VERBOSE = int(os.environ['API_RESPONSE_LESS_VERBOSE'])
        app.logger.info('Overriding API_RESPONSE_LESS_VERBOSE={}'.format(API_RESPONSE_LESS_VERBOSE))
    except Exception as ex:
        app.logger.error('Wrong env var value. Setting API_RESPONSE_LESS_VERBOSE=0 by default')

if "DEV_MODE" in os.environ:
    try:
        DEV_MODE = int(os.environ['DEV_MODE'])
        app.logger.info('Overriding DEV_MODE={}'.format(DEV_MODE))
    except Exception as ex:
        app.logger.error('Wrong env var value. Setting DEV_MODE=0 by default')

if "TLS" in os.environ:
    try:
        is_tls = int(os.environ['TLS'])
        if is_tls == 1:
            URL_SCHEME = 'https'
            app.logger.info('Enabling TLS={}'.format(is_tls))
    except Exception as ex:
        app.logger.error('Wrong env var value. Setting TLS=0 by default')

if "SECURITY_USER" in os.environ:
    security_user = os.environ['SECURITY_USER']
    if security_user and security_user.strip():
        SECURITY_USER = security_user.lower()
        app.logger.info('Setting SECURITY_USER')

if "SECURITY_PASS" in os.environ:
    security_pass = os.environ['SECURITY_PASS']
    if security_pass and security_pass.strip():
        SECURITY_PASS = security_pass
        app.logger.info('Setting SECURITY_PASS')

if SECURITY_USER and SECURITY_PASS:
    ENABLE_SECURITY_LOGIN = True
    app.logger.info('Enabling Security Login. ENABLE_SECURITY_LOGIN=True')

### swagger specific ###
SWAGGER_URL = '/allure-docker-service/swagger'
API_URL = '/allure-docker-service/swagger.json'
SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config = {
        'app_name': "Allure Docker Service"
    }
)
app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)
### end swagger specific ###

### Security Section
generate_security_swagger_specification()
blacklist = set()
jwt = JWTManager(app)

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist

@jwt.invalid_token_loader
def invalid_token_loader(msg):
    return jsonify({
        'meta_data': {
            'message': 'Invalid Token'
        }
    }), 401

@jwt.unauthorized_loader
def unauthorized_loader(msg):
    return jsonify({
        'meta_data': {
            'message': msg
        }
    }), 401

@jwt.expired_token_loader
def my_expired_token_callback(expired_token):
    token_type = expired_token['type']
    return jsonify({
        'meta_data': {
            'message': 'The {} token has expired'.format(token_type),
            'sub_status': 42,
        }
    }), 401

@jwt.revoked_token_loader
def revoked_token_loader():
    return jsonify({
        'meta_data': {
            'message': 'Revoked Token'
        }
    }), 401

def jwt_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if ENABLE_SECURITY_LOGIN:
            verify_jwt_in_request()
        return fn(*args, **kwargs)
    return wrapper
### end Security Section

### Security Endpoints Section
@app.route('/login', methods=['POST'], strict_slashes=False)
@app.route('/allure-docker-service/login', methods=['POST'], strict_slashes=False)
def login():
    try:
        content_type = request.content_type
        if content_type is None and content_type != 'application/json':
            raise Exception("Header 'Content-Type' must be 'application/json'")

        if not request.is_json:
            raise Exception("Missing JSON in body request")

        username = request.json.get('username', None)
        if not username:
            raise Exception("Missing 'username' attribute")

        password = request.json.get('password', None)
        if not password:
            raise Exception("Missing 'password' attribute")

        if SECURITY_USER != username.lower() or SECURITY_PASS != password:
            return jsonify({ 'meta_data': { 'message' : 'Invalid username/password' } }), 401

        json = {
            'data': {
                'access_token': create_access_token(identity=SECURITY_USER),
                'refresh_token': create_refresh_token(identity=SECURITY_USER)
            },
            'meta_data': {
                'message' : 'Successfully logged'
            }
        }
        return jsonify(json), 200
    except Exception as ex:
        body = {
            'meta_data': {
                'message' : str(ex)
            }
        }
        resp = jsonify(body)
        resp.status_code = 400
        return resp

@app.route('/logout', methods=['DELETE'], strict_slashes=False)
@app.route('/allure-docker-service/logout', methods=['DELETE'], strict_slashes=False)
@jwt_required
def logout():
    jti = get_raw_jwt()['jti']
    blacklist.add(jti)
    return jsonify({ 'meta_data': { 'message' : 'Successfully logged out' } }), 200


@app.route('/refresh', methods=['POST'], strict_slashes=False)
@app.route('/allure-docker-service/refresh', methods=['POST'], strict_slashes=False)
@jwt_refresh_token_required
def refresh():
    current_user = get_jwt_identity()
    json = {
        'data': {
            'access_token': create_access_token(identity=current_user)
        },
        'meta_data': {
            'message' : 'Successfully token obtained'
        }
    }
    return jsonify(json), 200
### end Security Endpoints Section

@app.route("/", strict_slashes=False)
@app.route("/allure-docker-service", strict_slashes=False)
def index():
    try:
        return render_template('index.html')
    except Exception as ex:
        body = {
            'meta_data': {
                'message' : str(ex)
            }
        }
        resp = jsonify(body)
        resp.status_code = 400
        return resp

@app.route("/swagger.json")
@app.route("/allure-docker-service/swagger.json", strict_slashes=False)
def swagger_json():
    try:
        specification_file = 'swagger.json'
        if ENABLE_SECURITY_LOGIN:
            specification_file = 'swagger_security.json'

        return send_file("{}/swagger/{}".format(STATIC_CONTENT, specification_file), mimetype='application/json')
    except Exception as ex:
        body = {
            'meta_data': {
                'message' : str(ex)
            }
        }
        resp = jsonify(body)
        resp.status_code = 400
        return resp

@app.route("/version", strict_slashes=False)
@app.route("/allure-docker-service/version", strict_slashes=False)
def version():
    f = None
    try:
        f = open(ALLURE_VERSION, "r")
        version = f.read()
    except Exception as ex:
        body = {
            'meta_data': {
                'message' : str(ex)
            }
        }
        resp = jsonify(body)
        resp.status_code = 400
    else:
        body = {
            'data': {
                'version': version.strip()
            },
            'meta_data': {
                'message' : "Version successfully obtained"
            }
        }
        resp = jsonify(body)
        resp.status_code = 200
    finally:
        if f is not None:
            f.close()

    return resp

@app.route("/ui/<path:path>")
@app.route("/allure-docker-service/ui/<path:path>")
def ui(path):
    try:
        return send_from_directory('{}/ui'.format(STATIC_CONTENT), path)
    except Exception as ex:
        body = {
            'meta_data': {
                'message' : str(ex)
            }
        }
        resp = jsonify(body)
        resp.status_code = 400
        return resp

@app.route("/latest-report", strict_slashes=False)
@app.route("/allure-docker-service/latest-report", strict_slashes=False)
@jwt_required
def latest_report():
    try:
        project_id = resolve_project(request.args.get('project_id'))
        if is_existent_project(project_id) is False:
            body = {
                'meta_data': {
                'message' : "project_id '{}' not found".format(project_id)
                }
            }
            resp = jsonify(body)
            resp.status_code = 404
            return resp

        project_report_latest_path = '/latest/{}'.format(REPORT_INDEX_FILE)
        url = url_for('get_reports', project_id=project_id, path=project_report_latest_path, redirect='false', _external=True)
        return redirect(url)
    except Exception as ex:
        body = {
            'meta_data': {
                'message' : str(ex)
            }
        }
        resp = jsonify(body)
        resp.status_code = 400
        return resp

@app.route("/send-results", methods=['POST'], strict_slashes=False)
@app.route("/allure-docker-service/send-results", methods=['POST'], strict_slashes=False)
@jwt_required
def send_results():
    try:
        content_type = request.content_type
        if content_type is None:
            raise Exception("Header 'Content-Type' should be 'application/json' or 'multipart/form-data'")

        if content_type != 'application/json' and content_type.startswith('multipart/form-data') is False:
            raise Exception("Header 'Content-Type' should be 'application/json' or 'multipart/form-data'")

        project_id = resolve_project(request.args.get('project_id'))
        if is_existent_project(project_id) is False:
            body = {
                'meta_data': {
                'message' : "project_id '{}' not found".format(project_id)
                }
            }
            resp = jsonify(body)
            resp.status_code = 404
            return resp

        processedFiles = []
        failedFiles = []
        validatedResults = []
        project_path = get_project_path(project_id)
        results_project='{}/results'.format(project_path)

        if content_type == 'application/json':
            json = request.get_json()

            if 'results' not in json:
                raise Exception("'results' array is required in the body")

            results = json['results']

            if  isinstance(results, list) == False:
                raise Exception("'results' should be an array")

            if not results:
                raise Exception("'results' array is empty")

            map_results = {}
            for result in results:
                if 'file_name' not in result or not result['file_name'].strip():
                    raise Exception("'file_name' attribute is required for all results")
                fileName = result.get('file_name')
                map_results[fileName] = ''

            if len(results) != len(map_results):
                raise Exception("Duplicated file names in 'results'")

            for result in results:
                file_name = result.get('file_name')
                validated_result = {}
                validated_result['file_name'] = file_name

                if 'content_base64' not in result or not result['content_base64'].strip():
                    raise Exception("'content_base64' attribute is required for '%s' file" % (file_name))
                else:
                    content_base64 = result.get('content_base64')
                    try:
                        validated_result['content_base64'] = base64.b64decode(content_base64)
                    except Exception:
                        raise Exception("'content_base64' attribute content for '%s' file should be encoded to base64" % (file_name))

                validatedResults.append(validated_result)

            for result in validatedResults:
                file_name = secure_filename(result.get('file_name'))
                content_base64 = result.get('content_base64')
                f = None
                try:
                    f = open("%s/%s" % (results_project, file_name), "wb")
                    f.write(content_base64)
                except Exception as ex:
                    error = {}
                    error['message'] = str(ex)
                    error['file_name'] = file_name
                    failedFiles.append(error)
                else:
                    processedFiles.append(file_name)
                finally:
                    if f is not None:
                        f.close()

        if content_type.startswith('multipart/form-data') is True:
            files = request.files.getlist('files[]')
            if not files:
                raise Exception("'files[]' array is empty")

            for file in files:
                try:
                    file_name = secure_filename(file.filename)
                    file.save("{}/{}".format(results_project, file_name))
                except Exception as ex:
                    error = {}
                    error['message'] = str(ex)
                    error['file_name'] = file_name
                    failedFiles.append(error)
                else:
                    processedFiles.append(file_name)

            validatedResults = processedFiles


        failedFilesCount = len(failedFiles)
        if failedFilesCount > 0:
            raise Exception('Problems with files: {}'.format(failedFiles))

        if API_RESPONSE_LESS_VERBOSE != 1:
            files = os.listdir(results_project)
            currentFilesCount = len(files)
            sentFilesCount = len(validatedResults)
            processedFilesCount = len(processedFiles)

    except Exception as ex:
        body = {
            'meta_data': {
                'message' : str(ex)
            }
        }
        resp = jsonify(body)
        resp.status_code = 400
    else:
        if API_RESPONSE_LESS_VERBOSE != 1:
            body = {
                'data': {
                    'current_files': files,
                    'current_files_count': currentFilesCount,
                    'failed_files': failedFiles,
                    'failed_files_count': failedFilesCount,
                    'processed_files': processedFiles,
                    'processed_files_count': processedFilesCount,
                    'sent_files_count': sentFilesCount
                    },
                'meta_data': {
                    'message' : "Results successfully sent for project_id '{}'".format(project_id)
                }
            }
        else:
            body = {
                'meta_data': {
                    'message' : "Results successfully sent for project_id '{}'".format(project_id)
                }
            }

        resp = jsonify(body)
        resp.status_code = 200

    return resp

@app.route("/generate-report", strict_slashes=False)
@app.route("/allure-docker-service/generate-report", strict_slashes=False)
@jwt_required
def generate_report():
    try:
        project_id = resolve_project(request.args.get('project_id'))
        if is_existent_project(project_id) is False:
            body = {
                'meta_data': {
                'message' : "project_id '{}' not found".format(project_id)
                }
            }
            resp = jsonify(body)
            resp.status_code = 404
            return resp

        files = None
        project_path=get_project_path(project_id)
        results_project='{}/results'.format(project_path)

        if API_RESPONSE_LESS_VERBOSE != 1:
            files = os.listdir(results_project)

        execution_name = request.args.get('execution_name')
        if execution_name is None or not execution_name:
            execution_name = 'Execution On Demand'

        execution_from = request.args.get('execution_from')
        if execution_from is None or not execution_from:
            execution_from = ''

        execution_type = request.args.get('execution_type')
        if execution_type is None or not execution_type:
            execution_type = ''

        check_process(KEEP_HISTORY_PROCESS, project_id)
        check_process(GENERATE_REPORT_PROCESS, project_id)

        exec_store_results_process='1'

        call([KEEP_HISTORY_PROCESS, project_id, ORIGIN])
        response = subprocess.Popen([GENERATE_REPORT_PROCESS, exec_store_results_process, project_id, ORIGIN, execution_name, execution_from, execution_type], stdout=subprocess.PIPE).communicate()[0]
        call([RENDER_EMAIL_REPORT_PROCESS, project_id, ORIGIN])

        build_order = 'latest'
        for line in response.decode("utf-8").split("\n") :
            if line.startswith("BUILD_ORDER"):
                build_order = line[line.index(':') + 1: len(line)]

        report_url = url_for('get_reports', project_id=project_id, path='{}/index.html'.format(build_order), _external=True)
    except Exception as ex:
        body = {
            'meta_data': {
                'message' : str(ex)
            }
        }
        resp = jsonify(body)
        resp.status_code = 400
    else:
        if files is not None:
            body = {
                'data': {
                    'report_url': report_url,
                    'allure_results_files': files
                },
                'meta_data': {
                    'message' : "Report successfully generated for project_id '{}'".format(project_id)
                }
            }
        else:
            body = {
                'data': {
                    'report_url': report_url
                },
                'meta_data': {
                    'message' : "Report successfully generated for project_id '{}'".format(project_id)
                }
            }

        resp = jsonify(body)
        resp.status_code = 200

    return resp

@app.route("/clean-history", strict_slashes=False)
@app.route("/allure-docker-service/clean-history", strict_slashes=False)
@jwt_required
def clean_history():
    try:
        project_id = resolve_project(request.args.get('project_id'))
        if is_existent_project(project_id) is False:
            body = {
                'meta_data': {
                'message' : "project_id '{}' not found".format(project_id)
                }
            }
            resp = jsonify(body)
            resp.status_code = 404
            return resp

        check_process(CLEAN_HISTORY_PROCESS, project_id)

        call([CLEAN_HISTORY_PROCESS, project_id, ORIGIN])
    except Exception as ex:
        body = {
            'meta_data': {
                'message' : str(ex)
            }
        }
        resp = jsonify(body)
        resp.status_code = 400
    else:
        body = {
            'meta_data': {
                'message' : "History successfully cleaned for project_id '{}'".format(project_id)
            }
        }
        resp = jsonify(body)
        resp.status_code = 200

    return resp

@app.route("/clean-results", strict_slashes=False)
@app.route("/allure-docker-service/clean-results", strict_slashes=False)
@jwt_required
def clean_results():
    try:
        project_id = resolve_project(request.args.get('project_id'))
        if is_existent_project(project_id) is False:
            body = {
                'meta_data': {
                'message' : "project_id '{}' not found".format(project_id)
                }
            }
            resp = jsonify(body)
            resp.status_code = 404
            return resp

        check_process(GENERATE_REPORT_PROCESS, project_id)
        check_process(CLEAN_RESULTS_PROCESS, project_id)

        call([CLEAN_RESULTS_PROCESS, project_id, ORIGIN])
    except Exception as ex:
        body = {
            'meta_data': {
                'message' : str(ex)
            }
        }
        resp = jsonify(body)
        resp.status_code = 400
    else:
        body = {
            'meta_data': {
                'message' : "Results successfully cleaned for project_id '{}'".format(project_id)
            }
        }
        resp = jsonify(body)
        resp.status_code = 200

    return resp

@app.route("/emailable-report/render", strict_slashes=False)
@app.route("/allure-docker-service/emailable-report/render", strict_slashes=False)
@jwt_required
def emailable_report_render():
    try:
        project_id = resolve_project(request.args.get('project_id'))
        if is_existent_project(project_id) is False:
            body = {
                'meta_data': {
                'message' : "project_id '{}' not found".format(project_id)
                }
            }
            resp = jsonify(body)
            resp.status_code = 404
            return resp

        check_process(GENERATE_REPORT_PROCESS, project_id)

        project_path=get_project_path(project_id)
        tests_cases_latest_report_project='{}/reports/latest/data/test-cases/*.json'.format(project_path)

        files = glob.glob(tests_cases_latest_report_project)
        testCases = []
        for fileName in files:
            with open(fileName) as f:
                jsonString = f.read()
                app.logger.debug("----TestCase-JSON----")
                app.logger.debug(jsonString)
                testCase = json.loads(jsonString)
                if testCase["hidden"] is False:
                    testCases.append(testCase)

        server_url = url_for('latest_report', project_id=project_id, _external=True)

        if "SERVER_URL" in os.environ:
            app.logger.info('Overriding Allure Server Url')
            server_url = os.environ['SERVER_URL']

        report = render_template(DEFAULT_TEMPLATE, css=EMAILABLE_REPORT_CSS, title=EMAILABLE_REPORT_TITLE, projectId=project_id, serverUrl=server_url, testCases=testCases)

        emailable_report_path = '{}/reports/{}'.format(project_path, EMAILABLE_REPORT_FILE_NAME)
        f = None
        try:
            f = open(emailable_report_path, "w")
            f.write(report)
        finally:
            if f is not None:
                f.close()
    except Exception as ex:
        body = {
            'meta_data': {
                'message' : str(ex)
            }
        }
        resp = jsonify(body)
        resp.status_code = 400
        return resp
    else:
        return report

@app.route("/emailable-report/export", strict_slashes=False)
@app.route("/allure-docker-service/emailable-report/export", strict_slashes=False)
@jwt_required
def emailable_report_export():
    try:
        project_id = resolve_project(request.args.get('project_id'))
        if is_existent_project(project_id) is False:
            body = {
                'meta_data': {
                'message' : "project_id '{}' not found".format(project_id)
                }
            }
            resp = jsonify(body)
            resp.status_code = 404
            return resp

        check_process(GENERATE_REPORT_PROCESS, project_id)

        project_path=get_project_path(project_id)
        emailable_report_path = '{}/reports/{}'.format(project_path, EMAILABLE_REPORT_FILE_NAME)

        report = send_file(emailable_report_path, as_attachment=True)
    except Exception as ex:
        message = str(ex)

        body = {
            'meta_data': {
                'message' : message
            }
        }
        resp = jsonify(body)
        resp.status_code = 400
        return resp
    else:
        return report

@app.route("/report/export", strict_slashes=False)
@app.route("/allure-docker-service/report/export", strict_slashes=False)
@jwt_required
def report_export():
    try:
        project_id = resolve_project(request.args.get('project_id'))
        if is_existent_project(project_id) is False:
            body = {
                'meta_data': {
                'message' : "project_id '{}' not found".format(project_id)
                }
            }
            resp = jsonify(body)
            resp.status_code = 404
            return resp

        check_process(GENERATE_REPORT_PROCESS, project_id)

        project_path=get_project_path(project_id)
        reports_project='{}/reports/latest'.format(project_path)

        tmp_dir = tempfile.mkdtemp()
        tmp_report = '{}/allure-report'.format(tmp_dir)
        shutil.copytree(reports_project, tmp_report)

        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w', zipfile.ZIP_DEFLATED) as zipf:
            rootDir = os.path.basename(tmp_report)
            for dirpath, dirnames, files in os.walk(tmp_report):
                for file in files:
                    filePath = os.path.join(dirpath, file)
                    parentPath = os.path.relpath(filePath, tmp_report)
                    arcname = os.path.join(rootDir, parentPath)
                    zipf.write(filePath, arcname)
        data.seek(0)

        shutil.rmtree(tmp_report, ignore_errors=True)

        report = send_file(
            data,
            mimetype='application/zip',
            as_attachment=True,
            attachment_filename='allure-docker-service-report.zip'
        )
    except Exception as ex:
        message = str(ex)

        body = {
            'meta_data': {
                'message' : message
            }
        }
        resp = jsonify(body)
        resp.status_code = 400
        return resp
    else:
        return report

@app.route("/projects", methods=['POST'], strict_slashes=False)
@app.route("/allure-docker-service/projects", methods=['POST'], strict_slashes=False)
@jwt_required
def create_project():
    try:
        if not request.is_json:
            raise Exception("Header 'Content-Type' is not 'application/json'")

        json = request.get_json()

        if 'id' not in json:
            raise Exception("'id' is required in the body")

        if isinstance(json['id'], str) is False:
            raise Exception("'id' should be string")

        if not json['id'].strip():
            raise Exception("'id' should not be empty")

        project_id_pattern = re.compile('^[a-z\d]([a-z\d -]*[a-z\d])?$')
        match = project_id_pattern.match(json['id'])
        if  match is None:
            raise Exception("'id' should contains alphanumeric lowercase characters or hyphens. For example: 'my-project-id'")

        project_id = json['id']
        if is_existent_project(project_id) is True:
            raise Exception("project_id '{}' is existent".format(project_id))

        if project_id == 'default':
            raise Exception("The id 'default' is not allowed. Try with another project_id")

        project_path=get_project_path(project_id)
        latest_report_project='{}/reports/latest'.format(project_path)
        results_project='{}/results'.format(project_path)

        if not os.path.exists(latest_report_project):
            os.makedirs(latest_report_project)

        if not os.path.exists(results_project):
            os.makedirs(results_project)
    except Exception as ex:
        body = {
            'meta_data': {
                'message' : str(ex)
            }
        }
        resp = jsonify(body)
        resp.status_code = 400
    else:
        body = {
            'data': {
                'id': project_id,
            },
            'meta_data': {
                'message' : "Project successfully created"
            }
        }
        resp = jsonify(body)
        resp.status_code = 201
    return resp

@app.route('/projects/<project_id>', methods=['DELETE'], strict_slashes=False)
@app.route("/allure-docker-service/projects/<project_id>", methods=['DELETE'], strict_slashes=False)
@jwt_required
def delete_project(project_id):
    try:
        if project_id == 'default':
            raise Exception("You must not remove project_id 'default'. Try with other projects")

        if is_existent_project(project_id) is False:
            body = {
                'meta_data': {
                'message' : "project_id '{}' not found".format(project_id)
                }
            }
            resp = jsonify(body)
            resp.status_code = 404
            return resp

        project_path=get_project_path(project_id)
        shutil.rmtree(project_path)
    except Exception as ex:
        body = {
            'meta_data': {
                'message' : str(ex)
            }
        }
        resp = jsonify(body)
        resp.status_code = 400
    else:
        body = {
            'meta_data': {
                'message' : "project_id: '{}' successfully removed".format(project_id)
            }
        }
        resp = jsonify(body)
        resp.status_code = 200
    return resp

@app.route('/projects/<project_id>', strict_slashes=False)
@app.route("/allure-docker-service/projects/<project_id>", strict_slashes=False)
@jwt_required
def get_project(project_id):
    try:
        if is_existent_project(project_id) is False:
            body = {
                'meta_data': {
                'message' : "project_id '{}' not found".format(project_id)
                }
            }
            resp = jsonify(body)
            resp.status_code = 404
            return resp

        project_reports_path = '{}/reports'.format(get_project_path(project_id))
        reports_entity = []

        directories = os.listdir(project_reports_path)
        for file in directories:
            file_path = '{}/{}/index.html'.format(project_reports_path, file)
            is_file = os.path.isfile(file_path)
            if is_file is True:
                report = url_for('get_reports', project_id=project_id, path='{}/index.html'.format(file), _external=True)
                reports_entity.append([report, os.path.getmtime(file_path), file])

        reports_entity.sort(key=lambda reports_entity:reports_entity[1], reverse=True)
        reports = []
        latest_report = None
        for report_entity in reports_entity:
            link = report_entity[0]
            if report_entity[2].lower() != 'latest':
                reports.append(link)
            else:
                latest_report = link

        if latest_report is not None:
            reports.insert(0, latest_report)

        body = {
            'data': {
                'project': {
                    'id': project_id,
                    'reports': reports
                },
            },
            'meta_data': {
                'message' : "Project successfully obtained"
                }
            }
        resp = jsonify(body)
        resp.status_code = 200
        return resp
    except Exception as ex:
        body = {
            'meta_data': {
                'message' : str(ex)
            }
        }
        resp = jsonify(body)
        resp.status_code = 400
        return resp

@app.route('/projects', strict_slashes=False)
@app.route("/allure-docker-service/projects", strict_slashes=False)
@jwt_required
def get_projects():
    try:
        directories = os.listdir(PROJECTS_DIRECTORY)
        projects = {}
        for project_name in directories:
            is_dir = os.path.isdir('{}/{}'.format(PROJECTS_DIRECTORY, project_name))
            if is_dir is True:
                project = {}
                project['uri'] = url_for('get_project', project_id=project_name, _external=True)
                projects[project_name] = project

        body = {
            'data': {
                'projects': projects,
            },
            'meta_data': {
                'message' : "Projects successfully obtained"
                }
            }
        resp = jsonify(body)
        resp.status_code = 200
        return resp
    except Exception as ex:
        body = {
            'meta_data': {
                'message' : str(ex)
            }
        }
        resp = jsonify(body)
        resp.status_code = 400
        return resp

@app.route('/projects/<project_id>/reports/<path:path>')
@app.route("/allure-docker-service/projects/<project_id>/reports/<path:path>")
@jwt_required
def get_reports(project_id, path):
    try:
        project_path = '{}/reports/{}'.format(project_id, path)
        return send_from_directory(PROJECTS_DIRECTORY, project_path)
    except Exception as ex:
        if(request.args.get('redirect') == 'false'):
            return send_from_directory(PROJECTS_DIRECTORY, project_path)
        return redirect(url_for('get_project', project_id=project_id, _external=True))


def is_existent_project(project_id):
    if not project_id.strip():
        return False
    return os.path.isdir(get_project_path(project_id))

def get_project_path(project_id):
    return '{}/{}'.format(PROJECTS_DIRECTORY, project_id)

def resolve_project(project_id_param):
    project_id = 'default'
    if project_id_param is not None:
        project_id = project_id_param
    return project_id

def check_process(process_file, project_id):
    tmp = os.popen('ps -Af | grep -w {}'.format(project_id)).read()
    proccount = tmp.count(process_file)

    if proccount > 0:
        raise Exception("Processing files for project_id '{}'. Try later!".format(project_id))

if __name__ == '__main__':
    if DEV_MODE == 1:
        app.logger.info('Stating in DEV_MODE')
        app.run(host=HOST, port=PORT)
    else:
        waitress.serve(app, threads=THREADS, host=HOST, port=PORT, url_scheme=URL_SCHEME)
