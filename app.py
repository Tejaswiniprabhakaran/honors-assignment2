import streamlit as st
import sqlite3
import bcrypt

# Connect to database
conn = sqlite3.connect('forum.db', check_same_thread=False)
c = conn.cursor()

# Create tables
def create_tables():
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, bio TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY, content TEXT, likes INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS likes (user_id INTEGER, post_id INTEGER, UNIQUE(user_id, post_id))''')
    conn.commit()

create_tables()

# Password hashing and verification
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# User functions
def register_user(username, password):
    hashed_pw = hash_password(password)
    try:
        c.execute('INSERT INTO users (username, password, bio) VALUES (?, ?, ?)', (username, hashed_pw, ''))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def login_user(username, password):
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    if user and verify_password(password, user[2]):
        return user
    return None

def update_profile(user_id, bio):
    c.execute('UPDATE users SET bio = ? WHERE id = ?', (bio, user_id))
    conn.commit()

def like_post(user_id, post_id):
    try:
        c.execute('INSERT INTO likes (user_id, post_id) VALUES (?, ?)', (user_id, post_id))
        c.execute('UPDATE posts SET likes = likes + 1 WHERE id = ?', (post_id,))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def add_initial_post():
    c.execute('SELECT * FROM posts')
    if not c.fetchall():
        c.execute('INSERT INTO posts (content, likes) VALUES (?, ?)', ('Welcome to the Forum! 🎉', 0))
        conn.commit()

# CSS styles
st.markdown("""
    <style>
    .main-title { font-size: 32px; color: #2E8B57; text-align: center; font-weight: bold; }
    .sub-title { font-size: 24px; color: #4682B4; font-weight: bold; }
    .post-container { background-color: #F0F8FF; padding: 15px; border-radius: 10px; margin-bottom: 20px; }
    .like-button { background-color: #FF6347; color: white; border-radius: 5px; }
    .profile-section { background-color: #FAEBD7; padding: 10px; border-radius: 10px; }
    </style>
""", unsafe_allow_html=True)

# App Layout
def main():
    st.markdown("<div class='main-title'>🌟 Streamlit Forum Application 🌟</div>", unsafe_allow_html=True)

    menu = ["Home", "Login", "Register"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Home":
        st.markdown("<div class='sub-title'>Forum Dashboard</div>", unsafe_allow_html=True)
        add_initial_post()
        c.execute('SELECT * FROM posts')
        posts = c.fetchall()
        for post in posts:
            st.markdown(f"<div class='post-container'>", unsafe_allow_html=True)
            st.write(f"**Post #{post[0]}**: {post[1]}")
            st.write(f"❤️ Likes: {post[2]}")
            if 'user' in st.session_state:
                if st.button(f"👍 Like Post #{post[0]}", key=f"like_{post[0]}", help="Give this post a like!"):
                    liked = like_post(st.session_state['user'][0], post[0])
                    if liked:
                        st.success("You liked the post!")
                    else:
                        st.warning("You've already liked this post.")
            st.markdown("</div>", unsafe_allow_html=True)

    elif choice == "Register":
        st.markdown("<div class='sub-title'>Register New Account</div>", unsafe_allow_html=True)
        username = st.text_input("Username")
        password = st.text_input("Password", type='password')
        if st.button("Register", help="Create your new account!"):
            registered = register_user(username, password)
            if registered:
                st.success("Account created successfully! Please go to Login.")
            else:
                st.error("Username already taken. Try another one.")

    elif choice == "Login":
        st.markdown("<div class='sub-title'>Login to Your Account</div>", unsafe_allow_html=True)
        username = st.text_input("Username")
        password = st.text_input("Password", type='password')
        if st.button("Login", help="Log in to access the dashboard"):
            user = login_user(username, password)
            if user:
                st.session_state['user'] = user
                st.success("Logged in successfully!")
                st.experimental_rerun()
            else:
                st.error("Incorrect username or password.")

    if 'user' in st.session_state:
        st.sidebar.markdown("<div class='sub-title'>Profile</div>", unsafe_allow_html=True)
        with st.sidebar:
            bio = st.text_area("Update your bio", st.session_state['user'][3], help="Write something about yourself!")
            if st.button("Update Profile"):
                update_profile(st.session_state['user'][0], bio)
                st.session_state['user'] = st.session_state['user'][:3] + (bio,)
                st.success("Profile updated!")

if __name__ == '__main__':
    main()




