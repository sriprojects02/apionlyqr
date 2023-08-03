import io
from PIL import Image
import base64
import qrcode
from flask import Flask, request, jsonify
import json, time, base64
import requests
import pyrebase

app = Flask(__name__)

firebase_config = {
    "apiKey": "AIzaSyBxirwjmjrrwdHCaoA2KnmEY9n2sI7BiBY",
    "authDomain": "theqronly.firebaseapp.com",
    "databaseURL": "https://theqronly-default-rtdb.firebaseio.com",
    "projectId": "theqronly",
    "storageBucket": "theqronly.appspot.com",
    "messagingSenderId": "946275450126",
    "appId": "1:946275450126:web:1c33be78492d64c25fab5f",
    "measurementId": "G-ZR73TMEDWF"
}

firebase = pyrebase.initialize_app(firebase_config)
storage = firebase.storage()

@app.route('/', methods=['GET'])
def home_page():
    data_set = {'Image': 'nothing to generate', 'Timestamp': time.time()}
    json_dump = json.dumps(data_set)
    return json_dump

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part in the request', 400

    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400

    try:
        # Upload the file to Firebase Storage
        filename = file.filename
        storage.child(filename).put(file)

        # Get the public URL of the uploaded file
        url = storage.child(filename).get_url(None)

        return url, 200
    except Exception as e:
        return str(e), 500

@app.route('/payment/', methods=['GET'])
def payment():
    # Accessing all request query parameters and parsing multiple parameters
    query_parameters = request.args.to_dict()

    # Creating the response JSON
    response = {
        'success': True,
        'code': 200,
        'data': query_parameters
    }
    idpay = query_parameters.get('payment_Id', '')
    amount = query_parameters.get('amount', '')
    sms_message = f"Payment received details are {idpay} and name is {amount}"

    json_dump=json.dumps(response)
    return json_dump


@app.route('/adddomain/', methods=['GET'])
def domain_page():
    api=str(request.args.get('api'))
    domain = str(request.args.get('domain'))
    customer = customerdata(api)
    if customer:
        customer['domain'] = domain
        data_set = {'message': 'domain added successfully.'}
        json_dump = json.dumps(data_set)
        return json_dump
    else:
        error_code = 302
        error_message = 'Admin panel: Could not add domain restriction. Error! Invalid API KEY'
        error_data = {'error_code': error_code, 'error_message': error_message}
        error_response = json.dumps(error_data)
        return error_response, error_code


@app.route('/statistics', methods=['GET'])
def request_page():
    api = str(request.args.get('api'))
    customer = customerdata(api)
    if customer:
        usage = customer['usage']
        data_set = {'usage': usage}
        json_dump = json.dumps(data_set)
        return json_dump
    else:
        error_code = 301
        error_message = 'Admin panel: Statistics could not be found. API KEY Invalid.'
        error_data = {'error_code': error_code, 'error_message': error_message}
        error_response = json.dumps(error_data)
        return error_response, error_code


@app.route('/user/', methods=['GET'])
def user_page():
    data = str(request.args.get('data'))
    api = str(request.args.get('apikey'))
    image_data = generate_qr_code(data)
    customer = customerdata(api)
    if customer:
        plan = customer['plan']
        usage = customer['usage']
        last_call_time = customer.get('last_call_time', 0)
        now = time.time()

        # Check if 24 hours have passed since the last call
        if now - last_call_time >= 86400:
            customer['usage'] = 0  # Reset the usage to 0 if 24 hours have passed

        if plan == "Free":
            if usage < 50:
                customer['usage'] += 1
                customer['last_call_time'] = now
                data_set = {'Image': image_data, 'Timestamp': time.time(), 'qrcodedata': data, 'plan': plan,
                            'usage': customer['usage']}
                json_dump = json.dumps(data_set)
                return json_dump
            else:
                error_code = 201
                error_message = 'Quota limit exceeded. Upgrade your account or try again after 24hrs.'
                error_data = {'error_code': error_code, 'error_message': error_message,
                              'last_call': customer['last_call_time']}
                error_response = json.dumps(error_data)
                return error_response, error_code

        elif plan == "premium":
            if usage < 200:
                customer['usage'] += 1
                customer['last_call_time'] = now
                customerdomain = customer['domain']
                accessed_domain = request.headers['Host']

                if customerdomain == accessed_domain or customerdomain == "":
                    data_set = {'Image': image_data, 'Timestamp': time.time(), 'qrcodedata': data, 'plan': plan,
                                'usage': customer['usage']}
                    json_dump = json.dumps(data_set)
                    return json_dump
                else:
                    error_code = 202
                    error_message = 'Access denied. Domain mismatch'
                    error_data = {'error_code': error_code, 'error_message': error_message, 'allowed_domain':customerdomain}
                    error_response = json.dumps(error_data)
                    return error_response, error_code

            else:
                error_code = 201
                error_message = 'Quota limit exceeded. Upgrade your account or try again after 24hrs.'
                error_data = {'error_code': error_code, 'error_message': error_message,
                              'last_call': customer['last_call_time']}
                error_response = json.dumps(error_data)
                return error_response, error_code

        else:
            data_set = {'Image': image_data, 'Timestamp': time.time(), 'qrcodedata': data, 'plan': plan}
            json_dump = json.dumps(data_set)
            return json_dump


    else:
        error_code = 404
        error_message = 'Wrong or invalid API Key provided.'
        error_data = {'error_code': error_code, 'error_message': error_message}
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
        'plan': 'Free'
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


def customerdata(apikey):
    global customer_list
    for customer in customer_list:
        if customer.get('apikey') == apikey:
            return customer
    return False


if __name__ == "__main__":
    app.config['CORS_HEADERS'] = 'Content-Type'
    app.run(port=7777, host='0.0.0.0')
