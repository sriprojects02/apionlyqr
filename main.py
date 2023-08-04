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

def generate_api_key(length=12):
    characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    api_key = ''.join(random.choice(characters) for _ in range(length))
    return api_key

@app.route('/signup/', methods=['GET'])
def signup_page():
    name=str(request.args.get('name'))
    email = str(request.args.get('email'))
    password = str(request.args.get('password'))
    number = str(request.args.get('number'))
    plan = str(request.args.get('plan'))
    usage = 0
    apikey = generate_api_key()
    if plan=='free':
        user_uid = create_firebase_user(email, password)
        if user_uid:
            print("User created with UID:", user_uid)
            result, status_code = save_user_data_to_firebase(user_uid, email, name, number, plan, apikey)
            print(result, status_code)
        else:
            print("User creation failed.")

    else:
        temp_api = "Pay now to generate your API Key"
        user_uid = create_firebase_user(email, password)
        if user_uid:
            print("User created with UID:", user_uid)
            result, status_code = save_user_data_to_firebase(user_uid, email, name, number, plan, temp_api)
            print(result, status_code)
        else:
            print("User creation failed.")


    new_customer = {
        'name': name,
        'email': email,
        'number':number,
        'apikey': apikey,
        'usage': usage,
        'plan': plan,
        'domain': ''
    }
    customer_list.append(new_customer)
    data_set={'message':'signed up successfully!'}
    json_dump = json.dumps(data_set)
    return json_dump


@app.route('/payment/', methods=['GET','POST'])
def payment():
    url = "https://www.fast2sms.com/dev/bulkV2"
    # Accessing all request query parameters and parsing multiple parameters
    query_parameters = request.get_json()

    # Creating the response JSON
    response = {
        'success': True,
        'code': 200,
        'data': query_parameters
    }
    json_dump=json.dumps(response)
    data = response['data']
    #transaction_id = data.get('payment_Id')
    #product = data.get('productTitle')
    email = data['email']
    phone = data['phone']
    status = data['status']
    #amount = data.get('amount')
    customer = customerdataforpayment(email)
    apikey = customer['apikey']
    mobile = phone[3:]
    if status=='paid' and customer:
        customer['paidstatus']=status
        today = datetime.date.today()
        expiry_date = today + datetime.timedelta(days=30)
        customer['expirydate']=expiry_date
        sms_message = f"Payment successful! Your API Key is {apikey} and it is valid upto {expiry_date}. Regards, OnlyQR Team"
        #sendsms to users with generated apikey
        querystring = {"authorization":"XfkiNo91q85uQCds0FZgy3tcwI74DjEKUHG6MAmprYSTRnvPxhHDrp5G92QI4nK8vzcCZBJ6wjih3Sbl","message":sms_message,"language":"english","route":"q","numbers":mobile}
        headers = {
        'cache-control': "no-cache"
        }
        response = requests.request("GET", url, headers=headers, params=querystring)
        save_api_to_firebase(mobile, email, apikey)


    else:
        data_set={'message':'customer not available or not paid status'}
        json_dump=json.dumps(data_set)
        print(json_dump)
        return json_dump

    data_set={'message':'payment done'}
    json_dump=json.dumps(data_set)
    return json_dump


@app.route('/removedomain/', methods=['GET'])
def remove_domain():
    api = str(request.args.get('api'))
    customer = customerdata(api)
    if customer:
        customer['domain']=''
        data_set = {'message':'domain removed successfully'}
        json_dump = json.dumps(data_set)
        return json_dump
    else:
        error_code = 302
        error_message = 'Admin panel: Error! Invalid API KEY'
        error_data = {'error_code': error_code, 'error_message': error_message}
        error_response = json.dumps(error_data)
        return error_response, error_code


@app.route('/upgradeplan', methods=['GET'])
def upgrade():
    api = str(request.aregs.get('api'))
    customer = customerdata(api)
    newplan = str(request.args.get('newplan'))
    if customer:
        customer['plan']=newplan
        data_set = {'message':'plan ugraded successfully'}
        json_dump = json.dumps(data_set)
        return json_dump
    else:
        error_code = 302
        error_message = 'Admin panel: Invalid API KEY'
        error_data = {'error_code': error_code, 'error_message': error_message}
        error_response = json.dumps(error_data)
        return error_response, error_code


@app.route('/adddomain/', methods=['GET'])
def domain_page():
    api=str(request.args.get('api'))
    domain = str(request.args.get('domain'))
    customer = customerdata(api)
    if customer:
        plan = customer['plan']
        if plan!='free':
            customer['domain'] = domain
            data_set = {'message': 'domain added successfully.'}
            json_dump = json.dumps(data_set)
            return json_dump
        else:
            error_code = 303
            error_message = 'Admin panel: Could not add domain restriction. Only for premium and platinum users!'
            error_data = {'error_code': error_code, 'error_message': error_message}
            error_response = json.dumps(error_data)
            return error_response, error_code

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
        plan = customer['plan']
        if plan!='free':
            usage = customer['usage']
            data_set = {'usage': usage}
            json_dump = json.dumps(data_set)
            return json_dump
        else:
            error_code = 301
            error_message = 'Admin panel: Statistics only for premium and platinum users.'
            error_data = {'error_code': error_code, 'error_message': error_message}
            error_response = json.dumps(error_data)
            return error_response, error_code

    else:
        error_code = 301
        error_message = 'Admin panel: Statistics could not be found. API KEY Invalid.'
        error_data = {'error_code': error_code, 'error_message': error_message}
        error_response = json.dumps(error_data)
        return error_response, error_code

def uploadfirebase(file, filename):
    try:
        # Upload the file to Firebase Storage
        filename = file.filename
        storage.child(filename).put(file)

        # Get the public URL of the uploaded file
        url = storage.child(filename).get_url(None)

        return url, 200

    except Exception as e:
        return str(e), 500


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
        
    customer = customerdata(apikey)
    
    if customer:
        plan = customer['plan']
        usage = customer['usage']
        last_call_time = customer.get('last_call_time', 0)
        now = time.time()
        if plan=='free':
            MAX_FILE_SIZE = 3 * 1024 * 1024
        elif plan=='premium':
            MAX_FILE_SIZE = 20 * 1024 * 1024
        else:
            MAX_FILE_SIZE = 50 * 1024 * 1024
        
        # Check if 24 hours have passed since the last call
        if now - last_call_time >= 86400:
            customer['usage'] = 0  # Reset the usage to 0 if 24 hours have passed

        if plan == "free":
            if usage < 5 and filesize < MAX_FILE_SIZE:
                customer['usage'] += 1
                customer['last_call_time'] = now
                data = uploadfirebase(file, filename)
                image_data = generate_qr_code(data)
                data_set = {'Image': image_data, 'Timestamp': time.time(), 'plan': plan,
                            'usage': customer['usage']}
                json_dump = json.dumps(data_set)
                return json_dump
            else:
                error_code = 201
                error_message = 'Quota limit exceeded or file size limit exceeded. Upgrade your account or try again after 24hrs.'
                error_data = {'error_code': error_code, 'error_message': error_message}
                error_response = json.dumps(error_data)
                return error_response, error_code

        elif plan == "premium":
            if usage < 20 and filesize < MAX_FILE_SIZE:
                customer['usage'] += 1
                customer['last_call_time'] = now
                data = uploadfirebase(file, filename)
                image_data = generate_qr_code(data)
                customerdomain = customer['domain']
                accessed_domain = request.headers['Host']

                if customerdomain == accessed_domain or customerdomain == "":
                    data_set = {'Image': image_data, 'Timestamp': time.time(), 'plan': plan,
                                'usage': customer['usage']}
                    json_dump = json.dumps(data_set)
                    return json_dump
                else:
                    error_code = 202
                    error_message = 'Access denied. Domain mismatch'
                    error_data = {'error_code': error_code, 'error_message': error_message,
                                  'allowed_domain': customerdomain}
                    error_response = json.dumps(error_data)
                    return error_response, error_code

            else:
                error_code = 201
                error_message = 'Quota limit exceeded. Upgrade your account or try again after 24hrs.'
                error_data = {'error_code': error_code, 'error_message': error_message,
                               'usage': customer['usage']}
                error_response = json.dumps(error_data)
                return error_response, error_code

        else:
            data = uploadfirebase(file, filename)
            image_data = generate_qr_code(data)
            data_set = {'Image': image_data, 'Timestamp': time.time(), 'plan': plan}
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
        'plan': 'free',
        'email': 'example@gmail.com',
        'paidstatus': 'failed',
        'expirydate':'2023-09-02'
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

def customerdataforpayment(email):
    global customer_list
    for customer in customer_list:
        if customer.get('email') == email:
            return customer
    return False

def create_firebase_user(email, password):
    firebase_auth_url = 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIzaSyBxirwjmjrrwdHCaoA2KnmEY9n2sI7BiBY'

    auth_data = {
        'email': email,
        'password': password,
        'returnSecureToken': True
    }

    try:
        response = requests.post(firebase_auth_url, json=auth_data)
        if response.status_code == 200:
            return response.json().get('localId')
        else:
            return None
    except Exception as e:
        return None

#save the apikey to firebase for premium and platinum users after payment is successfull
def save_api_to_firebase(phone, email, apikey):
    firebase_url = f'https://theqronly-default-rtdb.firebaseio.com/apikeys/{phone}.json'

    user_data = {
        'email': email,
        'apikey': apikey
    }

    try:
        response = requests.put(firebase_url, json=user_data)
        if response.status_code == 200:
            return "Data saved to Firebase successfully.", 200
        else:
            return "Error: Unable to save data to Firebase", 500
    except Exception as e:
        return f"Error: {e}", 500


def save_user_data_to_firebase(uid, email, name, mobile_number, plan, apikey):
    firebase_url = f'https://theqronly-default-rtdb.firebaseio.com/customer/{uid}.json'

    firebase_url2 = f'https://theqronly-default-rtdb.firebaseio.com/apikeys/{mobile_number}.json'

    user_data = {
        'email': email,
        'name': name,
        'mobile_number': mobile_number,
        'plan': plan,
    }

    user_data2 = {
        'apikey': apikey
    }

    try:
        response = requests.put(firebase_url, json=user_data)
        response2 = requests.put(firebase_url2, json=user_data2)

        if response.status_code == 200 and response2.status_code == 200:
            return "Data saved to Firebase successfully.", 200
        else:
            return "Error: Unable to save data to Firebase", 500
    except Exception as e:
        return f"Error: {e}", 500


if __name__ == "__main__":
    app.config['CORS_HEADERS'] = 'Content-Type'
    app.run(port=7777, host='0.0.0.0')
