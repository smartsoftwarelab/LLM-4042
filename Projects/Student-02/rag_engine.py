import os
import re
import pickle
import faiss
import numpy as np

from pathlib import Path

from sentence_transformers import (
    SentenceTransformer,
    CrossEncoder
)

from rank_bm25 import BM25Okapi

import requests
import vt
import asyncio
# === تست اتصال ===
if __name__ == "__main__":
    import asyncio
    asyncio.run(test_virustotal_connection())

VECTOR_DIR = Path(r"C:\Users\Somayye\knowledge_base\vector_db")
model = SentenceTransformer(
    "BAAI/bge-base-en-v1.5"
)

reranker = CrossEncoder(
    "cross-encoder/ms-marco-MiniLM-L-6-v2"
)
index = faiss.read_index(
    str(VECTOR_DIR / "faiss.index")
)

with open(VECTOR_DIR / "documents.pkl","rb") as f:
    documents = pickle.load(f)

with open(VECTOR_DIR / "ids.pkl","rb") as f:
    ids = pickle.load(f)

with open(VECTOR_DIR / "bm25.pkl","rb") as f:
    bm25 = pickle.load(f)
def tokenize(text):
    return re.findall(r"\b\w+\b", text.lower())
API_KEY = "API_KEY"

URL = "https://llm-test.ssl.qom.ac.ir/llm/v1/chat/completions"


VT_API_KEY = "f41b......."

def retrieve(query,
             faiss_k=10,
             bm25_k=10,
             final_k=5):

    ###########################
    # FAISS
    ###########################

    q = model.encode(
        [query],
        normalize_embeddings=True
    ).astype(np.float32)

    D, I = index.search(q, faiss_k)

    candidates = {}

    for score, idx in zip(D[0], I[0]):

        candidates[idx] = float(score)

    ###########################
    # BM25
    ###########################

    bm_scores = bm25.get_scores(
        tokenize(query)
    )

    top = np.argsort(bm_scores)[::-1][:bm25_k]

    for idx in top:
        candidates[idx] = max(
            candidates.get(idx, 0),
            bm_scores[idx]
        )

    ###########################
    # CrossEncoder
    ###########################

    pairs = [
    (query, documents[idx])
    for idx in candidates.keys()
    ]
    
    scores = reranker.predict(pairs)
    ###########################
     # Deduplicate
    ###########################
    
    unique = {}
    
    for idx, score in zip(candidates.keys(), scores):
    
        key = documents[idx].strip()
    
        if key not in unique or score > unique[key][1]:
    
            unique[key] = (idx, score)
    ranking = sorted(
        unique.values(),
        key=lambda x: x[1],
        reverse=True
    )

    # Similarity Threshold
    THRESHOLD = 0.35

    ranking = [x for x in ranking if x[1] >= THRESHOLD]

    ranking = ranking[:final_k]
    contexts=[]

    citations=[]

    for idx,score in ranking:

        contexts.append(documents[idx])

        citations.append(
            ids[idx]
        )

    return contexts,citations
    # ==========================================================
# Prompt + Ask Function
# ==========================================================

SYSTEM_PROMPT = """

You are a senior Cyber Threat Intelligence analyst.

You are also an expert in:
- Cybersecurity
- Malware Analysis
- Threat Intelligence
- Digital Forensics
- MITRE ATT&CK

Answer in Persian.

Use BOTH:

1. Your own cybersecurity knowledge.
2. The retrieved Context.

Rules:

- If the retrieved Context is relevant, use it as supporting evidence.
- If the Context is incomplete, use your own cybersecurity knowledge to complete the answer.
- If the Context is empty or irrelevant, answer using your own cybersecurity knowledge.
- Never contradict information explicitly stated in the Context.
- Do NOT invent information that conflicts with the Context.

Technical names must remain in English:
- MITRE IDs
- ATT&CK Techniques
- Malware names
- Windows APIs
- IOC
- Sigma Rules
- Registry Keys
- File names

Merge information from multiple documents.

Avoid repetition.

Summarize instead of copying paragraphs.

Use bullet points whenever possible.

Use tables only when appropriate.

References must contain ONLY the retrieved documents that were actually used.
If no reference is used:

DO NOT generate the References section.

Never write:
"اطلاعات کافی موجود نیست."

Simply omit the section.
Never generate MITRE IDs unless they exist in the Context.

Never invent Technique IDs.

Never invent API names.

Never invent IOC.

Never invent Sigma Rules.
Generate Detection only if the Context contains detection information.

Otherwise omit the section completely.

Response Style:
- Professional, clear and structured
- Use bullet points and tables where appropriate
- Be concise and useful (avoid repetition and long text)

"""
import re
import vt


def vt_lookup(ioc):

    with vt.Client(VT_API_KEY) as client:

        try:

            if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", ioc):
                obj = client.get_object(f"/files/{ioc}")

            elif ioc.startswith("http://") or ioc.startswith("https://"):
                obj = client.get_object(f"/urls/{vt.url_id(ioc)}")

            elif re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ioc):
                obj = client.get_object(f"/ip_addresses/{ioc}")

            else:
                obj = client.get_object(f"/domains/{ioc}")

            return {
                "type": obj.type,
                "reputation": getattr(obj, "reputation", 0),
                "stats": obj.last_analysis_stats,
                "meaningful_name": getattr(obj, "meaningful_name", "Unknown"),
                "size": getattr(obj, "size", "Unknown")
            }

        except Exception as e:

            print("[VirusTotal ERROR]", e)

            return None

def test_virustotal_connection():

    print("Testing VirusTotal...")

    with vt.Client(VT_API_KEY) as client:

        try:

            obj = client.get_object(
                "/files/44d88612fea8a8f36de82e1278abb02f"
            )

            print("Connected Successfully")

            print(obj.last_analysis_stats)

            return True

        except Exception as e:

            print(e)

            return False


def search_virustotal(query):

    ioc = None

    # HASH
    hash_match = re.search(
        r"\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b",
        query
    )
    if hash_match:
        ioc = hash_match.group(0)

    # URL
    if not ioc:
        url_match = re.search(r"https?://[^\s]+", query)
        if url_match:
            ioc = url_match.group(0)

    # IP
    if not ioc:
        ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", query)
        if ip_match:
            ioc = ip_match.group(0)

    # DOMAIN
    if not ioc:
        domain_match = re.search(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", query)
        if domain_match:
            ioc = domain_match.group(0)

    if not ioc:
        return None

    result = vt_lookup(ioc)

    if result is None:
        return None

    print(type(result))
    print(result)
    stats = result["stats"]
    return f"""
VirusTotal Analysis

IOC: {ioc}

Malicious: {stats.get('malicious',0)}
Suspicious: {stats.get('suspicious',0)}
Harmless: {stats.get('harmless',0)}
Undetected: {stats.get('undetected',0)}

Reputation: {result.get('reputation')}
Type: {result.get('type')}
"""
def ask(question, history=None):
    text = question.strip()
    lower_text = text.lower()
    
    # ====================== HANDLERهای هوشمند ======================
    
    # ۱. خداحافظی
    if any(word in lower_text for word in ["خداحافظ", "بای", "خدانگهدار", "bye", "goodbye"]):
        return "خدانگهدار 🌹 موفق باشید! هر وقت نیاز به تحلیل داشتی، برگرد."
    
    # ۲. تشکر
    if any(word in lower_text for word in ["ممنون", "مرسی", "تشکر", "متشکرم", "thank", "thanks"]):
        return "خواهش می‌کنم 🌹 خوشحالم که تونستم کمک کنم."
    
    # ۳. سلام / احوالپرسی
    if len(text.split()) <= 6 and any(g in lower_text for g in ["سلام", "سلام خوبی", "حالت چطوره", "خوبی", "hello", "hi", "درود"]):
        if any(k in lower_text for k in ["هش", "فایل", "بررسی", "تحلیل", "check", "hash", "file", "آپلود", "این", "اون"]):
            pass
        else:
            return """
سلام 🌹
امیدوارم حالت خوب باشه. آماده‌ام تا در زمینه **تحلیل بدافزار**، **MITRE ATT&CK**، **IOC**، **Sigma Rule** و Threat Intelligence بهت کمک کنم.
هش، فایل، IP، Domain یا هر سوالی داری بگو.
"""
    
    # ====================== آماده‌سازی history ======================
    history_text = ""
    if history:
        for m in history[-6:]:
            role = "کاربر" if m["role"] == "user" else "دستیار"
            history_text += f"{role}: {m['content']}\n"

    # ====================== Retrieve Context ======================
    contexts, citations = retrieve(question)

    # ====================== VirusTotal ======================
    if len(contexts) == 0:
        context = "No relevant context found."
    else:
        context = "\n\n".join(contexts)

    vt_result = search_virustotal(question)
    if vt_result:
        context += f"""
=========================
VirusTotal Result
=========================
{vt_result}
⚠️ IMPORTANT: Use the EXACT numbers from the VirusTotal Result above. 
Do NOT round or approximate the detection counts.
"""
    
    print("================ CONTEXT ================")
    print(context)
    print("========================================")
    
    # ====================== ساخت prompt ======================
    history_text = ""
    if history:
        for m in history[-6:]:
            role = "کاربر" if m["role"] == "user" else "دستیار"
            history_text += f"{role}: {m['content']}\n"
    
    prompt = f"""
{SYSTEM_PROMPT}
=========================
Conversation History
=========================
{history_text}

=========================
Context
=========================
{context}
=========================
VirusTotal Exact Numbers (USE THESE):
=========================
{vt_result if vt_result else 'No VT data'}

=========================
Question
=========================
{question}

=========================
Output Format
=========================
# پاسخ
- حداکثر ۵ خط
- فقط خلاصه مفهوم

# خلاصه
به صورت Bullet شامل:
- هدف
- کاربرد
- سیستم‌عامل
- مهم‌ترین ویژگی

# جزئیات فنی
- حداکثر ۶ Bullet
- از کپی کردن متن Context خودداری کن.
- اطلاعات مشابه را ادغام کن.

اگر Sub-technique وجود داشت فقط به صورت جدول:
| Sub-technique | MITRE ID | توضیح کوتاه |

اگر API وجود داشت فقط به صورت جدول:
| API | نقش |

# IOC
⚠️ اگر IOC وجود ندارد، این بخش را کاملاً حذف کن و ننویس.

# Detection
⚠️ اگر اطلاعات کافی برای Detection وجود ندارد، این بخش را کاملاً حذف کن و ننویس.

# Mitigation
⚠️ اگر اطلاعات کافی برای Mitigation وجود ندارد، این بخش را کاملاً حذف کن و ننویس.

# MITRE Mapping
فقط به صورت جدول:
| Technique | ID |

⚠️ اگر هیچ Technique پیدا نشد، این بخش را کاملاً حذف کن.

# References
⚠️ اگر هیچ منبعی استفاده نشده، این بخش را کاملاً حذف کن و اصلاً ننویس.

Important:
- Do NOT write "اطلاعات کافی موجود نیست" anywhere.
- If you don't have information for a section, DELETE that section completely.
- Do NOT create empty or placeholder sections.
- Keep the answer concise and easy to read.
"""

    # ================================================================
    # 👇 اینجا رو با کد جدید جایگزین کنید 👇
    # ================================================================
    
    print("Before LLM")

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "CoreStableLLM",
        "messages": [
            {
                "role": "system",
                "content": SYSTEM_PROMPT
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
    }
        # DEBUG - Check prompt length
    print(f"\n{'='*50}")
    print(f"[DEBUG] Prompt length: {len(prompt)} chars")
    print(f"[DEBUG] Context length: {len(context)} chars")
    print(f"[DEBUG] Question length: {len(question)} chars")
    print(f"{'='*50}\n")
    response = requests.post(
        URL,
        headers=headers,
        json=payload,
        timeout=200
    )

    response.raise_for_status()
    response = response.json()
    answer = response["choices"][0]["message"]["content"]

    print("After LLM")
    print("\n" + "=" * 70)
    
    # ========================
    # اضافه کردن منابع (References)
    # ========================
        # ========================
    # حذف References تکراری از LLM
    # ========================
    if "## 📚 References" in answer:
        answer = answer.split("## 📚 References")[0].strip()
    if "## References" in answer:
        answer = answer.split("## References")[0].strip()
    
    # ========================
    # اضافه کردن منابع از citations
    # ========================
    if citations:
        references_section = "\n\n---\n## 📚 References\n\n"
        for i, c in enumerate(citations, 1):
            ref_line = f"[{i}] {c['source']} - {c['name']}"
            references_section += ref_line + "\n"
            print(ref_line)
        final_answer = answer + references_section
    else:
        final_answer = answer
        print("No citations found")
    
    print(f"[DEBUG] Final answer length: {len(final_answer)} chars")
    print(f"[DEBUG] Has VT result: {'VirusTotal' in context}")
    print(f"[DEBUG] Has citations: {bool(citations)}")
    
    return final_answer
    
    # ========================
    # ترکیب پاسخ نهایی
    # ========================
    final_answer = answer + references_section
    
    print(f"[DEBUG] Final answer length: {len(final_answer)} chars")
    print(f"[DEBUG] Has VT result: {'VirusTotal' in context}")
    print(f"[DEBUG] Has citations: {bool(citations)}")
    
    return final_answer