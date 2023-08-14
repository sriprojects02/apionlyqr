import io
from PIL import Image
import base64
import qrcode
from flask import Flask, request, jsonify
import json, time, base64
import requests
import datetime
import random
import pyrebase

app = Flask(__name__)
# Firebase configuration
firebase_config = {
    "apiKey": "AIzaSyCU7m9dzyFg2dri3J02bYwMbm2Rb8M5hDs",
    "authDomain": "qronly-fileqr-cyberclips.firebaseapp.com",
    "databaseURL": "https://qronly-fileqr-cyberclips-default-rtdb.asia-southeast1.firebasedatabase.app",
    "projectId": "qronly-fileqr-cyberclips",
    "storageBucket": "qronly-fileqr-cyberclips.appspot.com",
    "messagingSenderId": "960001609342",
    "appId": "1:960001609342:web:9e3b335dbf819255db122f"
}

firebase = pyrebase.initialize_app(firebase_config)
storage = firebase.storage()
auth = firebase.auth()
db = firebase.database()


@app.route('/', methods=['GET'])
def home_page():
    data_set = {'Image': 'nothing to generate', 'Timestamp': time.time()}
    json_dump = json.dumps(data_set)
    return json_dump


def search_customer_by_api_key(api_key):
    try:
        data = db.child('customerfileqr').get()
        for customer_uid, customer_data in data.val().items():
            if 'apikey' in customer_data and customer_data['apikey'] == api_key:
                # Found the customer with the given API key
                return customer_data

        # If the loop completes without finding a customer with the given API key
        return None
    except Exception as e:
        # Error occurred while retrieving data
        print("Error:", e)
        return None


@app.route('/statistics/', methods=['GET'])
def statistics():
    apikey = str(request.args.get('apikey'))
    customer = search_customer_by_api_key(apikey)
    if customer is not None:
        usage = customer['usage']
        data_set = {'message': 'statistics fetched successfully', 'usage': usage}
        json_dump = json.dumps(data_set)
        return json_dump
    else:
        data_set = {'message': 'failed to fetch! No Customer matched!'}
        json_dump = json.dumps(data_set)
        return json_dump


@app.route('/signup/', methods=['GET', 'POST'])
def signup():
    apikey = str(request.args.get('apikey'))
    name = str(request.args.get('name'))
    email = str(request.args.get('email'))
    uid = str(request.args.get('uid'))
    mobile_number = str(request.args.get('number'))
    plan = str(request.args.get('plan'))
    domain = str(request.args.get('domain'))
    usage = 0
    now = time.time()

    if not all([apikey, name, email, uid, mobile_number, plan]):
        data_set = {'message': 'Missing parameters', 'errorcode': 208}
        json_dump = json.dumps(data_set)
        return json_dump

    customer = search_customer_by_api_key(apikey)
    if customer is not None:
        data_set = {'message': 'Your account is already active. We cannot signup a new account with your details!'}
        json_dump = json.dumps(data_set)
        return json_dump

    savesignup = save_user_data_to_firebase(uid, email, name, usage, mobile_number, plan, apikey, now, domain)
    if savesignup == "Data saved to Firebase successfully.":
        data_set = {'message': 'signed up successfully!'}
    else:
        data_set = {'message': 'Something went wrong!', 'error': savesignup}
    json_dump = json.dumps(data_set)
    return json_dump


@app.route('/adddomain/', methods=['GET'])
def domain_page():
    api = str(request.args.get('api'))
    domain = str(request.args.get('domain'))
    customer = search_customer_by_api_key(api)
    if customer is not None:
        plan = customer['plan']
        uid = customer['uid']
        if plan != 'free':
            restricted = adddomainrestriction(uid, domain)
            if restricted == "Domain Added successfully":
                data_set = {'message': 'domain added successfully.'}
            else:
                data_set = {'message': 'Something Wrong at our end!', 'error': restricted}
            json_dump = json.dumps(data_set)
            return json_dump
        else:
            error_code = 303
            error_message = 'Admin panel: Could not add domain restriction. Only for premium and platinum users!'
            error_data = {'error_code': error_code, 'message': error_message}
            error_response = json.dumps(error_data)
            return error_response, error_code

    else:
        error_code = 302
        error_message = 'Admin panel: Could not add domain restriction. Error! Invalid API KEY'
        error_data = {'error_code': error_code, 'message': error_message}
        error_response = json.dumps(error_data)
        return error_response, error_code


def uploadfirebase(file, filename):
    try:
        # Upload the file to Firebase Storage
        filename = file.filename
        storage.child(filename).put(file)

        # Get the public URL of the uploaded file
        url = storage.child(filename).get_url(None)

        return url

    except Exception as e:
        return str(e)


@app.route('/upload/', methods=['POST'])
def upload_file():
    apikey = str(request.args.get('apikey'))
    if 'file' not in request.files:
        return 'No file part in the request', 400

    file = request.files['file']
    file.seek(0, 2)
    filesize = file.tell()
    file.seek(0)
    filename = file.filename
    if file.filename == '':
        return 'No selected file', 400

    customer = search_customer_by_api_key(apikey)

    if customer is not None:
        plan = customer['plan']
        uid = customer['uid']
        expiry = customer['expiry']
        last_call_time = customer['last_call_time']
        customerdomain = customer['domain']
        now = time.time()
        timestamp_str = str(now).replace('.', 'time')
        accessed_domain1 = request.headers['Host']
        if plan == 'free':
            MAX_FILE_SIZE = 3 * 1024 * 1024
        elif plan == 'premium':
            MAX_FILE_SIZE = 15 * 1024 * 1024
        else:
            MAX_FILE_SIZE = 30 * 1024 * 1024

        # Check if 24 hours have passed since the last call
        if now - last_call_time >= 86400:
            resetusage(uid, 0)  # Reset the usage to 0 if 24 hours have passed

        usage = customer['usage']
        if plan == "free":
            if usage < 5 and filesize < MAX_FILE_SIZE:
                usage += 1
                last_call_time = now
                incrementusage(uid, usage, last_call_time)
                data = uploadfirebase(file, filename)
                image_data = generate_qr_code(data)
                history = save_history_to_firebase(timestamp_str, data, usage, uid, accessed_domain1)
                data_set = {'Image': image_data, 'Timestamp': time.time(), 'plan': plan, 'history': history,
                            'usage': customer['usage']}
                json_dump = json.dumps(data_set)
                return json_dump
            else:
                error_code = 201
                error_message = 'Quota limit exceeded or file size limit exceeded. Upgrade your account or try again after 24hrs.'
                error_data = {'error_code': error_code, 'message': error_message}
                error_response = json.dumps(error_data)
                return error_response, error_code

        elif plan == 'premium' and expiry == '':
            if usage < 20 and filesize < MAX_FILE_SIZE:
                usage += 1
                last_call_time = now
                incrementusage(uid, usage, last_call_time)
                data = uploadfirebase(file, filename)
                image_data = generate_qr_code(data)
                history = save_history_to_firebase(timestamp_str, data, usage, uid, accessed_domain1)
                accessed_domain = request.headers['Host']

                if customerdomain == accessed_domain or customerdomain == "":
                    data_set = {'Image': image_data, 'Timestamp': time.time(), 'plan': plan, 'history': history,
                                'usage': customer['usage']}
                    json_dump = json.dumps(data_set)
                    return json_dump
                else:
                    error_code = 202
                    error_message = 'Access denied. Domain mismatch'
                    error_data = {'error_code': error_code, 'message': error_message,
                                  'allowed_domain': customerdomain}
                    error_response = json.dumps(error_data)
                    return error_response, error_code

            else:
                error_code = 201
                error_message = 'Quota limit exceeded or plan expired! Recharge or Upgrade your account and try again after 10 minutes.'
                error_data = {'error_code': error_code, 'message': error_message,
                              'usage': customer['usage']}
                error_response = json.dumps(error_data)
                return error_response, error_code

        else:
            if filesize < MAX_FILE_SIZE:
                usage += 1
                last_call_time = now
                incrementusage(uid, usage, last_call_time)
                data = uploadfirebase(file, filename)
                image_data = generate_qr_code(data)
                history = save_history_to_firebase(timestamp_str, data, usage, uid, accessed_domain1)
                accessed_domain = request.headers['Host']

                if customerdomain == accessed_domain or customerdomain == "":
                    data_set = {'Image': image_data, 'Timestamp': time.time(), 'plan': plan, 'history': history,
                                'usage': customer['usage']}
                    json_dump = json.dumps(data_set)
                    return json_dump
                else:
                    error_code = 202
                    error_message = 'Access denied. Domain mismatch'
                    error_data = {'error_code': error_code, 'message': error_message,
                                  'allowed_domain': customerdomain}
                    error_response = json.dumps(error_data)
                    return error_response, error_code

            else:
                error_code = 201
                error_message = 'Quota limit exceeded. Upgrade your account or try again after 24hrs.'
                error_data = {'error_code': error_code, 'message': error_message,
                              'usage': customer['usage']}
                error_response = json.dumps(error_data)
                return error_response, error_code


    else:
        error_code = 404
        error_message = 'Wrong or invalid API Key provided.'
        error_data = {'error_code': error_code, 'message': error_message}
        error_response = json.dumps(error_data)
        return error_response, error_code


@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'  # Allow requests from any origin
    response.headers[
        'Access-Control-Allow-Headers'] = 'Content-Type,Authorization'  # Add any additional headers you want to allow
    response.headers[
        'Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'  # Add any HTTP methods you want to allow
    return response


def generate_qr_code(data):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )

    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    # Save the image to a BytesIO object
    image_bytes = io.BytesIO()
    img.save(image_bytes, format='PNG')

    # Encode the image as a base64 string
    image_base64 = base64.b64encode(image_bytes.getvalue()).decode('utf-8')

    return image_base64


customer_list = [
    {
        'name': 'Customer 1',
        'apikey': 'd09f3e56-c9a5-4b1b-8c8d-ec5b29af2e12',
        'usage': 0,
        'plan': 'free',
        'email': 'example@gmail.com',
        'paidstatus': 'failed',
        'expirydate': '2023-09-02'
    },
    {
        'name': 'Customer 2',
        'apikey': 'a4bc32d8-67fe-4b2e-aaf9-5ce1f4281c71',
        'usage': 0,
        'domain': 'google.com',
        'plan': 'premium'
    },
    {
        'name': 'Customer 3',
        'apikey': '0098-temp-890-api',
        'usage': 0,
        'plan': 'platinum'
    },
    # Add more customers as needed
]


def incrementusage(uid, usage, last_call_time):
    firebase_url = f'https://qronly-fileqr-cyberclips-default-rtdb.asia-southeast1.firebasedatabase.app/customerfileqr/{uid}.json'
    user_data = {
        'usage': usage,
        'last_call_time': last_call_time
    }
    try:
        response = requests.patch(firebase_url, json=user_data)
        if response.status_code == 200:
            return "Usage Resetted successfully", 200
        else:
            return "Error", 500
    except Exception as e:
        return f"Error: {e}", 500


def adddomainrestriction(uid, domain):
    firebase_url = f'https://qronly-fileqr-cyberclips-default-rtdb.asia-southeast1.firebasedatabase.app/customerfileqr/{uid}.json'
    user_data = {
        'domain': domain
    }
    try:
        response = requests.patch(firebase_url, json=user_data)
        if response.status_code == 200:
            return "Domain Added successfully"
        else:
            return response.status_code
    except Exception as e:
        return f"Error: {e}", 500


def resetusage(uid, usage):
    firebase_url = f'https://qronly-fileqr-cyberclips-default-rtdb.asia-southeast1.firebasedatabase.app/customerfileqr/{uid}.json'
    user_data = {
        'usage': usage
    }
    try:
        response = requests.patch(firebase_url, json=user_data)
        if response.status_code == 200:
            return "Usage Resetted successfully", 200
        else:
            return "Error", 500
    except Exception as e:
        return f"Error: {e}", 500


def save_user_data_to_firebase(uid, email, name, usage, mobile_number, plan, apikey, now, domain):
    firebase_url = f'https://qronly-fileqr-cyberclips-default-rtdb.asia-southeast1.firebasedatabase.app/customerfileqr/{uid}.json'

    firebase_url2 = f'https://theqronly-default-rtdb.firebaseio.com/customerfileqr/{uid}.json'

    user_data = {
        'email': email,
        'uid': uid,
        'name': name,
        'mobile_number': mobile_number,
        'plan': plan,
        'apikey': apikey,
        'usage': usage,
        'expiry': '',
        'domain': domain,
        'last_call_time': now
    }

    try:
        response = requests.put(firebase_url, json=user_data)
        response2 = requests.put(firebase_url2, json=user_data)

        if response.status_code == 200 and response2.status_code == 200:
            return "Data saved to Firebase successfully."
        else:
            return response.status_code
    except Exception as e:
        return f"Error: {e}", 500


def save_history_to_firebase(now, data, usage, uid):
    firebase_url = f'https://theqronly-default-rtdb.firebaseio.com/historyfileqr/{uid}/{now}.json'

    user_data = {
        'data': data,
        'usage': usage,
        'time': now,
    }

    try:
        response = requests.put(firebase_url, json=user_data)

        if response.status_code == 200:
            return "Saved to History.", 200
        else:
            # Print the response content when there's an error
            print(response.content)
            return f"Error: Unable to save history to server. Status code: {response.status_code}", response.status_code
    except requests.exceptions.RequestException as e:
        # Catch any exception related to the request (e.g., connection error, timeout, etc.)
        return f"Error: {e}", 500
    except Exception as e:
        # Catch any other unexpected exceptions
        return f"Error: {e}", 500


if __name__ == "__main__":
    app.config['CORS_HEADERS'] = 'Content-Type'
    app.run(port=7777, host='0.0.0.0')
