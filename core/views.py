# core/views.py


import json
import numpy as np
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .utils.feature_utils import feature_extract, process_sequences
from tensorflow.keras.models import load_model
from tokenizers import ByteLevelBPETokenizer
import pandas as pd
from django.shortcuts import render
from zxcvbn import zxcvbn
import hashlib
from .models import UsedPassword
from .utils.ai_client import query_local_ai


# === Load model and tokenizer ===
model = load_model("core/input/model.h5")
tokenizer = ByteLevelBPETokenizer("core/input/vocab.json", "core/input/merges.txt")

# === Load token table ===
token_table = pd.read_csv("core/input/token_lookup.csv")
if 'Unnamed: 0' in token_table.columns:
    token_table.drop(columns=['Unnamed: 0'], inplace=True)
flat_token_to_index = dict(zip(token_table['Token'], token_table['Index']))

# === Load dictionaries ===
with open("core/input/top10000common.json", "r", encoding="utf-8") as f:
    common_words = json.load(f)

common_password_df = pd.read_json("core/input/top10000password.json")
common_password_list = common_password_df[123456].tolist()

with open("core/input/data.json", "r") as f:
    keyboard_pattern_list = json.load(f)

# === Strength labels & mappings ===
mapping = {'very_high': 4, 'high': 3, 'medium': 2, 'low': 1, 'very_low': 0, 'none': 1}
strength_labels = {0: 'Weak', 1: 'Medium', 2: 'Strong'}

# === Rule-based logic ===
def rules2(p): return any(ord(p[i+1]) == ord(p[i]) + 1 and ord(p[i+2]) == ord(p[i+1]) + 1 for i in range(len(p) - 2))
def rules3(p): return any(p[i] == p[i+1] == p[i+2] for i in range(len(p) - 2))
def rules4(p, common): return any(word in p.lower() for word in common)
def rules5(p, common):
    subs = str.maketrans({"@":"a", "0":"o", "1":"l", "3":"e", "$":"s", "5":"s"})
    normalized = p.lower().translate(subs)
    return any(word in normalized for word in common)
def rules6(p, common): return p.lower() in common
def rules7(p, personal): return any(info.lower() in p.lower() for info in personal)
def rules8(p, username): return username.lower() in p.lower()
def rules9(p): return False
def rules10(p, patterns): return any(pattern in p for pattern in patterns)
def rules11(p, common): return any(word[::-1] in p.lower() for word in common)
def rules12(p): return any(str(y) in p for y in range(1900, 2101))
def rules13(p): return len(p) % 2 == 0 and p[:len(p)//2] == p[len(p)//2:]
def rules14(p): return len(set(p)) < 4

def run_all_rules(password, features, common_words, common_passwords, keyboard_patterns, personal_data=None, username=""):
    violated_rules = []
    feat = features.tolist()[0] if hasattr(features, 'tolist') else features

    if feat[0] < 8:
        violated_rules.append("Length must be >= 8")
    if any(feat[i] < 1 for i in range(1, 5)):
        violated_rules.append("Must include all character types")
    if rules2(password): violated_rules.append("Sequential characters")
    if rules3(password): violated_rules.append("Repetitive characters")
    if rules4(password, common_words): violated_rules.append("Common dictionary word")
    if rules5(password, common_words): violated_rules.append("Obfuscated common word")
    if rules6(password, common_passwords): violated_rules.append("In common password list")
    if rules7(password, personal_data): violated_rules.append("Personal info used")
    if rules8(password, username): violated_rules.append("Username used")
    if rules9(password): violated_rules.append("Keyboard pattern")
    if rules10(password, keyboard_patterns): violated_rules.append("Keyboard sequence")
    if rules11(password, common_words): violated_rules.append("Reversed dictionary word")
    if rules12(password): violated_rules.append("Contains year")
    if rules13(password): violated_rules.append("Repeated halves")
    if rules14(password): violated_rules.append("Low entropy")
    return violated_rules

@csrf_exempt
def analyze_password(request):
    if request.method == "POST":
        data = json.loads(request.body)
        password = data.get("password", "")
        username = data.get("username", "")

        # Extract features
        feat = feature_extract(password)
        feat = [mapping[item] if isinstance(item, str) and item in mapping else item for item in feat]
        features = np.array([feat[:10]], dtype=np.float32)

        # Tokenize
        seq_tokens = tokenizer.encode(password).tokens
        VOCAB_SIZE = getattr(tokenizer, 'vocab_size', 64)
        indices = [min(flat_token_to_index.get(tok, 0), VOCAB_SIZE - 1) for tok in seq_tokens]
        padded_seq = np.array(process_sequences([indices], 61), dtype=np.int32)

        # Predict
        preds = model.predict({'input_seq': padded_seq, 'input_eng': features}, verbose=0)
        pred_class = int(np.argmax(preds, axis=1)[0])
        label = strength_labels.get(pred_class, 'Unknown')

        # Rule evaluation
        violated = run_all_rules(password, features, common_words, common_password_list, keyboard_pattern_list, {"john", "doe"}, username)
        rule_score = max(0, 100 - len(violated) * 5)
        verdict = "Strong" if rule_score >= 85 else "Medium" if rule_score >= 76 else "Weak"

        zxcvbn_result = zxcvbn(password)
        crack_times = zxcvbn_result.get("crack_times_display", {})

        def get_time(key):
            return crack_times.get(key) or "Not available"
        
        ai_suggestions = query_local_ai()

        return JsonResponse({
            "Password": password,
            "ML_Prediction": label,
            "Rule_Violations": violated,
            "Rule_Based_Score": rule_score,
            "Final_Verdict": verdict,
            "ZXCVBN_CrackTimes": {
                "online_throttling_100_per_hour": get_time("online_throttling_100_per_hour"),
                "online_no_throttling_10_per_second": get_time("online_no_throttling_10_per_second"),
                "offline_slow_hashing_1e4_per_second": get_time("offline_slow_hashing_1e4_per_second"),
                "offline_fast_hashing_1e10_per_second": get_time("offline_fast_hashing_1e10_per_second")
            },
            "AI_Password_Suggestions": ai_suggestions
        })

def home(request):
    return render(request, 'core/home.html')


@csrf_exempt
def remember_phrase(request):
    if request.method == "POST":
        body = json.loads(request.body)
        password = body.get("password", "")
        prompt = f"Create a fun, memorable sentence to help remember this strong password: {password}"
        
        # Use the API key from environment variable
        ai_suggestions = query_local_ai(prompt)        
        return JsonResponse(ai_suggestions)
       
        
        


@csrf_exempt
def make_unpredictable_password(request):
    if request.method == "POST":
        body = json.loads(request.body)
        password = body.get("password", "")

        prompt = f"""
        Improve the password "{password}" by increasing its entropy and making it more secure.
        Keep it slightly recognizable but much harder to guess.
        Use a mix of uppercase, lowercase, numbers, and symbols.
        Provide ONLY one strong version, no explanation.
        """

        ai_suggestions = query_local_ai(prompt)

        try:
           
            return JsonResponse(ai_suggestions)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)



def save_password(request):
    if request.method == "POST":
        data = json.loads(request.body)
        password = data.get("password")

        # Hash the password securely
        hashed = hashlib.sha256(password.encode()).hexdigest()

        if UsedPassword.objects.filter(hashed_password=hashed).exists():
            return JsonResponse({ "exists": True })
        else:
            UsedPassword.objects.create(hashed_password=hashed)
            return JsonResponse({ "exists": False })


