# ===========================
# app.py - نسخه اصلاح شده
# ===========================

import streamlit as st
import os
import time
from rag_engine_test import ask

st.set_page_config(
    page_title="Cyber Threat Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>

/* ---------- Hide Streamlit default elements ---------- */
#MainMenu,
footer,
header,
[data-testid="stToolbar"],
[data-testid="collapsedControl"] {
    visibility: hidden;
    height: 0;
}

/* ---------- Full Dark Theme ---------- */
html, body, [data-testid="stAppViewContainer"], .stApp {
    background: #0b1220 !important;
    color: #ffffff !important;
}

[data-testid="stHeader"] {
    background: #0b1220 !important;
}

/* ---------- Chat Messages - متن سفید ---------- */
[data-testid="stChatMessage"] {
    background: #151d2d !important;
    border: 1px solid #27344b;
    border-radius: 14px;
    padding: 12px;
}

[data-testid="stChatMessage"] p,
[data-testid="stChatMessage"] span,
[data-testid="stChatMessage"] div,
[data-testid="stChatMessage"] li,
[data-testid="stChatMessage"] strong,
[data-testid="stChatMessage"] h1,
[data-testid="stChatMessage"] h2,
[data-testid="stChatMessage"] h3 {
    color: #ffffff !important;
}

[data-testid="stChatMessage"] a {
    color: #00ff88 !important;
}

[data-testid="stChatMessage"] code {
    color: #00ff88 !important;
    background: #0b1220 !important;
    padding: 2px 6px;
    border-radius: 4px;
}

[data-testid="stChatMessage"] table {
    color: #ffffff !important;
}

[data-testid="stChatMessage"] th {
    color: #00ff88 !important;
    background: #1a2733 !important;
}

[data-testid="stChatMessage"] td {
    color: #ffffff !important;
    background: #151d2d !important;
}

/* ---------- Title ---------- */
.block-container {
    padding-top: 20px !important;
    max-width: 1100px;
    padding-bottom: 100px !important;
}

h1 {
    color: white !important;
}

/* ---------- Bottom Bar Container ---------- */
.bottom-bar {
    position: fixed;
    left: 50%;
    transform: translateX(-50%);
    bottom: 20px;
    width: 65%;
    max-width: 900px;
    background: #161f30;
    border: 1px solid #31415f;
    border-radius: 18px;
    padding: 8px 10px;
    z-index: 9999;
    display: flex;
    align-items: center;
    gap: 5px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.5);
}

/* ---------- Upload Button ---------- */
.upload-btn-wrapper .stButton > button {
    background: transparent !important;
    border: 1px solid #31415f !important;
    color: #b7c2d0 !important;
    font-size: 20px !important;
    padding: 8px 12px !important;
    border-radius: 12px !important;
    height: 44px !important;
    width: 44px !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    transition: all 0.2s !important;
}

.upload-btn-wrapper .stButton > button:hover {
    background: #31415f !important;
    color: #00ff88 !important;
    border-color: #00ff88 !important;
}

/* ---------- Chat Input ---------- */
.chat-input-wrapper .stChatInput > div {
    background: transparent !important;
    border: none !important;
    padding: 0 !important;
}

.chat-input-wrapper .stChatInput input {
    background: transparent !important;
    border: none !important;
    color: #ffffff !important;
    padding: 10px 15px !important;
    font-size: 15px !important;
}

.chat-input-wrapper .stChatInput input::placeholder {
    color: #6b7b8d !important;
}

/* ---------- File in Message ---------- */
.file-in-message {
    background: #1a2733;
    border: 1px solid #00ff8866;
    border-radius: 12px;
    padding: 10px 15px;
    margin-top: 8px;
}

/* ---------- Pending File Badge ---------- */
.pending-file-badge {
    position: fixed;
    bottom: 80px;
    left: 50%;
    transform: translateX(-50%);
    z-index: 9999;
    background: #00ff8822;
    border: 1px solid #00ff88;
    color: #00ff88;
    padding: 6px 16px;
    border-radius: 20px;
    font-size: 13px;
}

/* Hide default file uploader */
[data-testid="stFileUploader"] {
    position: fixed !important;
    top: -1000px !important;
    visibility: hidden !important;
    height: 0 !important;
    width: 0 !important;
}

/* ---------- Misc ---------- */
.bottom-bar .stColumn {
    padding: 0 !important;
}
/* ---------- حذف کادر اضافی ---------- */
.bottom-bar .stButton {
    border: none !important;
    background: transparent !important;
}

div[data-testid="stVerticalBlock"] > div:has(.bottom-bar) {
    border: none !important;
    background: transparent !important;
}
</style>
""", unsafe_allow_html=True)

# ===========================
# Title
# ===========================
st.title("🛡️ Cyber Threat Intelligence Assistant")
st.caption("Threat Intelligence • Malware Analysis • IOC Lookup")

# ===========================
# Initialize Session State
# ===========================
if "messages" not in st.session_state:
    st.session_state.messages = []

if "pending_file" not in st.session_state:
    st.session_state.pending_file = None

if "uploader_key" not in st.session_state:
    st.session_state.uploader_key = 0

# ===========================
# Display Chat History
# ===========================
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg.get("content", ""))
        
        file_info = msg.get("file_info")
        if file_info and isinstance(file_info, dict):
            st.markdown(f"""
            <div class="file-in-message">
                📎 <strong style="color:#00ff88;">{file_info.get('name', 'Unknown')}</strong>
                <span style="color:#b7c2d0; font-size:12px; margin-right:8px;">
                    | {file_info.get('size', 0)} bytes
                </span>
            </div>
            """, unsafe_allow_html=True)

# ===========================
# Hidden File Uploader
# ===========================
uploaded_file = st.file_uploader(
    "Upload",
    type=['exe', 'dll', 'pdf', 'docx', 'zip', 'rar', 'js', 'vbs', 'ps1', 
          'bat', 'txt', 'csv', 'json', 'xml', 'html', 'eml', 'pcap'],
    key=f"hidden_uploader_{st.session_state.uploader_key}",
    label_visibility="collapsed"
)

if uploaded_file is not None:
    st.session_state.pending_file = {
        'name': uploaded_file.name,
        'size': uploaded_file.size,
        'type': uploaded_file.type if uploaded_file.type else "application/octet-stream",
        'data': uploaded_file.getvalue()
    }
    st.session_state.uploader_key += 1
    st.rerun()

# ===========================
# Bottom Bar
# ===========================
st.markdown('<div class="bottom-bar"><div class="upload-btn-wrapper">', unsafe_allow_html=True)

col_upload, col_chat = st.columns([0.7, 7])

with col_upload:
    if st.button("📎", key="upload_trigger", help="آپلود فایل برای تحلیل"):
        st.components.v1.html("""
        <script>
        (function() {
            var inputs = window.parent.document.querySelectorAll('input[type="file"]');
            if (inputs.length > 0) {
                inputs[inputs.length - 1].click();
            }
        })();
        </script>
        """, height=0)

with col_chat:
    prompt = st.chat_input("سوال خود را درباره بدافزار، IOCs یا تکنیک‌های حمله بپرسید...")

st.markdown('</div></div>', unsafe_allow_html=True)

# ===========================
# Pending File Badge
# ===========================
if st.session_state.pending_file:
    st.markdown(f"""
    <div class="pending-file-badge">
        📎 فایل آماده: {st.session_state.pending_file['name']} 
        ({st.session_state.pending_file['size']} bytes)
    </div>
    """, unsafe_allow_html=True)

# ===========================
# پردازش ورودی
# ===========================
def process_input(user_prompt):
    """پردازش ورودی کاربر"""
    
    question = user_prompt
    file_info = None
    
    if st.session_state.pending_file:
        file_info = st.session_state.pending_file
        question = user_prompt + f"\n\n[فایل آپلود شده: {file_info['name']} | سایز: {file_info['size']} bytes]"
    
    user_msg = {
        "role": "user",
        "content": user_prompt
    }
    
    if file_info:
        user_msg["file_info"] = {
            "name": file_info["name"],
            "size": file_info["size"],
            "type": file_info["type"]
        }
    
    st.session_state.messages.append(user_msg)
    
    try:
        with st.spinner("🔄 در حال تحلیل و جستجو در پایگاه دانش..."):
            history = st.session_state.messages[:-1] if len(st.session_state.messages) > 1 else None
            response = ask(question, history=history)
            
            if not response:
                response = "❌ پاسخی دریافت نشد. لطفاً دوباره تلاش کنید."
    
    except Exception as e:
        response = f"⚠️ خطا در پردازش: {str(e)}"
    
    st.session_state.messages.append({
        "role": "assistant",
        "content": response
    })
    
    st.session_state.pending_file = None

# ===========================
# اجرا
# ===========================
if prompt:
    process_input(prompt)
    st.rerun()

elif st.session_state.pending_file and not prompt:
    auto_question = f"لطفاً فایل {st.session_state.pending_file['name']} را تحلیل کن و تهدیدات آن را بررسی کن."
    process_input(auto_question)
    st.rerun()

# ===========================
# Sidebar
# ===========================
with st.sidebar:
    st.header("📊 Session Info")
    
    msg_count = len(st.session_state.messages)
    file_count = sum(1 for msg in st.session_state.messages if msg.get("file_info"))
    
    st.metric("Messages", msg_count)
    st.metric("Files", file_count)
    
    st.divider()
    
    if st.button("🗑️ Clear History", type="secondary", use_container_width=True):
        st.session_state.messages = []
        st.session_state.pending_file = None
        st.rerun()
    
    st.divider()
    
    st.subheader("💡 نمونه سوالات")
    sample_questions = [
        "تحلیل هش 44d88612fea8a8f36de82e1278abb02f",
        "WannaCry چیست و چطور کار می‌کند؟",
        "تکنیک Process Injection در MITRE ATT&CK",
    ]
    
    for q in sample_questions:
        if st.button(q, key=f"sample_{q[:20]}", use_container_width=True):
            process_input(q)
            st.rerun()