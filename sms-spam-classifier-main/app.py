import streamlit as st
import sqlite3
import pickle
import string
import nltk
from nltk.corpus import stopwords
from nltk.stem.porter import PorterStemmer
from cryptography.fernet import Fernet
import jwt
import time
from functools import wraps



# NLTK Resources
nltk.download('punkt')
nltk.download('stopwords')

ps = PorterStemmer()
SECRET_KEY = b'VtL1aUt8xk3_vOwy6Mxqx5tTe6g8fAdflbr1v8Fcw3I='
key = Fernet.generate_key()  # This is used to generate a random key for Fernet
cipher = Fernet(key)



# ========== DATABASE SETUP ==========
def create_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def signup_user(username, password):
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False

def login_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
    data = c.fetchone()
    conn.close()
    return data



# ========== TEXT PROCESSING ==========
def transform_text(text):
    text = text.lower()
    text = nltk.word_tokenize(text)
    y = [ps.stem(i) for i in text if i.isalnum() and i not in stopwords.words('english')]
    return " ".join(y)

def encrypt_message(message, secret_key):
    try:
        cipher = Fernet(secret_key)
        return cipher.encrypt(message.encode()).decode()
    except Exception as e:
        return f"Error encrypting message: {str(e)}"

def decrypt_message(encrypted_message, secret_key):
    try:
        cipher = Fernet(secret_key)
        return cipher.decrypt(encrypted_message.encode()).decode()
    except Exception as e:
        return f"Error decrypting message: {str(e)}"



# ========== JWT AUTH ==========
def generate_token(username):
    expiration = time.time() + 3600
    payload = {"username": username, "exp": expiration}
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token

def decode_jwt(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        raise Exception("Token expired.")
    except jwt.InvalidTokenError:
        raise Exception("Invalid token.")

def require_authentication(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = st.session_state.get("jwt_token")
        if not token:
            st.error("Unauthorized access. Please log in.")
            return
        try:
            decode_jwt(token)
            return func(*args, **kwargs)
        except Exception as e:
            st.error(f"Authentication error: {str(e)}")
    return wrapper



# ========== MODEL & VECTORIZER ==========
try:
    tfidf = pickle.load(open('vectorizer.pkl', 'rb'))
    model = pickle.load(open('model.pkl', 'rb'))
except Exception as e:
    st.error(f"Error loading model/vectorizer: {e}")
    st.stop()



# ========== UI/UX Design ==========
create_db()
st.title("🔐 Encrypted SMS Spam Classifier")

menu = st.sidebar.selectbox("Choose Option", ["Login", "Signup", "Classifier"])




# ========== SIGNUP ==========
if menu == "Signup":
    st.subheader("Create Account")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")
    if st.button("Signup"):
        if signup_user(new_user, new_pass):
            st.success("Account created. Go to Login.")
        else:
            st.error("Username already exists.")



# ========== LOGIN ==========
elif menu == "Login":
    st.subheader("Login")
    user = st.text_input("Username")
    passwd = st.text_input("Password", type="password")
    if st.button("Login"):
        result = login_user(user, passwd)
        if result:
            token = generate_token(user)
            st.session_state.jwt_token = token
            st.success("Login successful! Go to Classifier.")
        else:
            st.error("Invalid credentials")



# ========== SPAM CLASSIFIER ==========
elif menu == "Classifier":
    @require_authentication
    def run_classifier():
        st.subheader("SMS Spam Classifier")

        input_sms = st.text_area("Enter your message")
        secret_key = st.text_input("Enter Secret Key", type="password")

        if st.button('Encrypt & Predict'):
            if input_sms.strip() == "" or not secret_key:
                st.warning("Please enter a message and a secret key.")
            else:
                try:
                    # Validate the secret key length
                    if len(secret_key) != 44:
                        st.error("Invalid secret key. Fernet keys must be 32 url-safe base64-encoded bytes.")
                        return
                    
                    # Encrypt and decrypt the message using the provided secret key
                    encrypted_msg = encrypt_message(input_sms, secret_key)
                    st.info(f"🔒 Encrypted:\n\n{encrypted_msg}")

                    decrypted_msg = decrypt_message(encrypted_msg, secret_key)
                    st.success(f"🔓 Decrypted:\n\n{decrypted_msg}")

                    transformed_sms = transform_text(decrypted_msg)
                    vector_input = tfidf.transform([transformed_sms])
                    result = model.predict(vector_input)[0]

                    if result == 1:
                        st.error("🚫 Spam")
                    else:
                        st.success("✅ Not Spam")
                except Exception as e:
                    st.error(f"Error: {e}")

    run_classifier()
