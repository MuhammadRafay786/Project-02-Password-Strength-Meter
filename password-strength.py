import streamlit as st
import re
import secrets
import string
import math
import hashlib
import requests
from typing import Dict, Optional, List
import logging
from pathlib import Path
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.FileHandler("security.log"), logging.StreamHandler()])
logger = logging.getLogger("PasswordAnalyzer")

class PasswordSecurityEngine:
    SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    def __init__(self):
        self.blacklist = self._init_blacklist()
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'PasswordAnalyzer/1.0', 'Accept': 'application/json'})
        self.cache = {}

    def _init_blacklist(self) -> set:
        default = {"password", "123456", "qwerty", "admin", "welcome", "letmein", "sunshine", "iloveyou", "monkey", "football"}
        try:
            path = Path("blacklist.txt")
            if not path.exists():
                path.write_text("\n".join(default), encoding="utf-8")
                logger.info("Created default blacklist file")
            return set(path.read_text(encoding="utf-8").lower().splitlines())
        except Exception as e:
            logger.error(f"Blacklist initialization failed: {e}")
            return default

    def analyze_password(self, password: str) -> Dict:
        if not password:
            return {'score': 0, 'strength': 'Critical', 'entropy': 0.0, 'feedback': ["Password cannot be empty."], 'breaches': 0}
        normalized_pwd = password.strip().lower()
        if normalized_pwd in self.blacklist:
            return {'score': 0, 'strength': 'Critical', 'length': len(password), 'complexity': self._check_complexity(password),
                    'entropy': self._calculate_entropy(password), 'breaches': self._check_breaches(password),
                    'feedback': ['This password is in common password blacklist']}
        complexity = self._check_complexity(password)
        entropy = self._calculate_entropy(password)
        breaches = self._check_breaches(password)
        score = self._calculate_score(len(password), complexity, entropy, breaches)
        strength = self._determine_strength(score)
        feedback = self._generate_recommendations(len(password), complexity, entropy, breaches)
        return {'score': score, 'strength': strength, 'length': len(password), 'complexity': complexity, 'entropy': entropy, 'breaches': breaches, 'feedback': feedback}

    def _check_complexity(self, pwd: str) -> Dict:
        return {'lower': bool(re.search(r'[a-z]', pwd)), 'upper': bool(re.search(r'[A-Z]', pwd)),
                'digit': bool(re.search(r'\d', pwd)), 'special': bool(re.search(fr'[{re.escape(self.SPECIAL_CHARS)}]', pwd))}

    def _calculate_entropy(self, pwd: str) -> float:
        if not pwd: return 0.0
        freq = {}
        for c in pwd:
            freq[c] = freq.get(c, 0) + 1
        shannon = sum(-(v/len(pwd)) * math.log2(v/len(pwd)) for v in freq.values())
        charset = sum([26 if re.search(r'[a-z]', pwd) else 0, 26 if re.search(r'[A-Z]', pwd) else 0,
                       10 if re.search(r'\d', pwd) else 0, len(self.SPECIAL_CHARS) if any(c in self.SPECIAL_CHARS for c in pwd) else 0])
        combinatorial = math.log2(charset ** len(pwd)) if charset else 0
        return max(shannon, combinatorial)

    def _check_breaches(self, pwd: str) -> int:
        try:
            if pwd in self.cache: return self.cache[pwd]
            digest = hashlib.sha1(pwd.encode()).hexdigest().upper()
            prefix, suffix = digest[:5], digest[5:]
            response = self.session.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=3)
            if response.status_code == 200:
                for line in response.text.splitlines():
                    if line.startswith(suffix):
                        count = int(line.split(':')[1])
                        self.cache[pwd] = count
                        return count
                self.cache[pwd] = 0
                return 0
            return -1
        except Exception as e:
            logger.error(f"Breach check failed: {e}")
            return -1

    def _calculate_score(self, length: int, complexity: Dict, entropy: float, breaches: int) -> int:
        score = min(length * 2, 25) + sum(complexity.values()) * 7.5 + min(entropy, 30) + (15 if breaches == 0 else 0)
        return min(int(score), 100)

    def _determine_strength(self, score: int) -> str:
        if score >= 90: return "Excellent"
        if score >= 75: return "Strong"
        if score >= 50: return "Moderate"
        if score >= 25: return "Weak"
        return "Critical"

    def _generate_recommendations(self, length: int, complexity: Dict, entropy: float, breaches: int) -> List[str]:
        recs = []
        if length < 12: recs.append("Increase password length to at least 12 characters")
        if not complexity['lower']: recs.append("Add lowercase letters")
        if not complexity['upper']: recs.append("Add uppercase letters")
        if not complexity['digit']: recs.append("Include numbers")
        if not complexity['special']: recs.append("Add special characters")
        if breaches > 0: recs.append(f"Change password immediately (found in {breaches} breaches)")
        if entropy < 60: recs.append("Increase complexity with more character variety")
        return recs

    def generate_password(self, length: int = 16) -> str:
        if length < 8: length = 8
        chars = string.ascii_letters + string.digits + self.SPECIAL_CHARS
        while True:
            pwd = [secrets.choice(string.ascii_uppercase), secrets.choice(string.ascii_lowercase),
                   secrets.choice(string.digits), secrets.choice(self.SPECIAL_CHARS)] + [secrets.choice(chars) for _ in range(length-4)]
            secrets.SystemRandom().shuffle(pwd)
            candidate = ''.join(pwd)
            if all(self._check_complexity(candidate).values()): return candidate

def set_page_config():
    st.set_page_config(page_title="Password Strength Analyzer", page_icon="🔒", layout="wide")
    st.title("🔐 Password Strength Analyzer")
    st.markdown("Analyze your password strength or generate a secure one with ease!")

def set_theme():
    theme = st.sidebar.selectbox("Choose Theme", ["Light", "Dark"])
    if theme == "Dark":
        st.markdown("""
        <style>
        .stApp { background: linear-gradient(135deg, #1a1a2e, #16213e, #0f3460); color: #e0e0e0; }
        .stButton>button { background-color: #F63366; color: white; border-radius: 8px; }
        .stTextInput>div>input { background-color: #2e2e3e; color: #e0e0e0; border-radius: 8px; }
        .stSlider>div { color: #e0e0e0; }
        </style>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <style>
        .stApp { background: linear-gradient(135deg, #f5f7fa, #c3cfe2, #e0c3fc); color: #262730; }
        .stButton>button { background-color: #F63366; color: white; border-radius: 8px; }
        .stTextInput>div>input { background-color: #ffffff; color: #262730; border-radius: 8px; }
        </style>
        """, unsafe_allow_html=True)

def analyze_password_tab(analyzer):
    st.header("Analyze Your Password")
    password = st.text_input("Enter your password:", type="password")
    if st.button("Analyze"):
        if password:
            with st.spinner("Analyzing..."):
                result = analyzer.analyze_password(password)
                display_analysis_results(result)
        else:
            st.error("Please enter a password.")

def display_analysis_results(result):
    breach_count = result.get('breaches', 0)
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Security Score", f"{result['score']}/100")
    with col2:
        st.metric("Strength", result['strength'])
    with col3:
        st.metric("Entropy", f"{result['entropy']:.1f} bits")
    if result['feedback']:
        st.subheader("Recommendations")
        for item in result['feedback']:
            st.warning(item)
    elif result['score'] >= 80:
        st.success("Excellent password! It’s strong and secure.")
    display_breach_info(breach_count)

def display_breach_info(breach_count):
    if breach_count is None:
        st.warning("Breach check unavailable.")
    elif breach_count > 0:
        st.error(f"⚠️ Found in {breach_count} breaches!")
    else:
        st.success("No breaches detected.")

def generate_password_tab(analyzer):
    st.header("Generate a Secure Password")
    length = st.slider("Password Length", 8, 36, 12, step=4)
    if st.button("Generate"):
        with st.spinner("Generating..."):
            new_password = analyzer.generate_password(length)
        st.success(f"Generated Password: **{new_password}**")
        st.info("This password is cryptographically secure with a mix of characters.")
        if st.button("Copy to Clipboard"):
            st.write(f'<script>copyToClipBoard("{new_password}")</script>', unsafe_allow_html=True)
            st.success("Copied to clipboard!")

def main():
    set_page_config()
    set_theme()
    # st.markdown(f"<script>{js}</script>", unsafe_allow_html=True)
    analyzer = PasswordSecurityEngine()
    tab1, tab2 = st.tabs(["🔍 Analyze Password", "✨ Generate Password"])
    with tab1:
        analyze_password_tab(analyzer)
    with tab2:
        generate_password_tab(analyzer)

if __name__ == "__main__":
    main()