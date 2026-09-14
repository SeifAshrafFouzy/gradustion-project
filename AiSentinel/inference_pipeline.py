import joblib
import pandas as pd
import time
import os

# تأكدي إن الاستدعاء ده مطابق لاسم الدالة جوه rolling.py عندك
from anomaly.rolling import get_rolling_features
from anomaly.preprocessing import PreSplitPreprocessor

class InferencePipeline:
    def __init__(self):
        base_path = os.path.dirname(os.path.abspath(__file__))
        artifacts_path = os.path.join(base_path, "artifacts")
        
        # 1. تحميل الـ Preprocessing والـ Scalers الخاصين بالـ Isolation Forest فقط
        self.post = joblib.load(os.path.join(artifacts_path, "postsplit.pkl"))
        self.scaler_if = joblib.load(os.path.join(artifacts_path, "scaler_if.pkl"))
        self.pca = joblib.load(os.path.join(artifacts_path, "pca_if.pkl"))

        # 2. تحميل موديل الـ Isolation Forest والـ Metadata بتاعته فقط
        self.if_model = joblib.load(os.path.join(artifacts_path, "isolation_forest.pkl"))
        self.if_meta = joblib.load(os.path.join(artifacts_path, "if_metadata.pkl"))

    def predict(self, raw_log: dict, model_type: str = "if"):
        """🌟 الدالة الوحيدة اللي الباك إند بيكلمها"""
        try:
            now = time.time()
            safe_log = raw_log.copy()

            # --- خطوة 1: تنظيف وتوحيد الـ IP ---
            if "ip" not in safe_log:
                safe_log["ip"] = safe_log.get("source_ip", safe_log.get("client_ip", "127.0.0.1"))

            raw_ip = str(safe_log.get("ip", "0.0.0.0")).strip()
            clean_ip = raw_ip.split(":")[0] if ":" in raw_ip else raw_ip
            safe_log["ip"] = clean_ip

            if "status" not in safe_log: 
                safe_log["status"] = 200

            # --- خطوة 2: المعالجة الاستاتيكية ---
            pre = PreSplitPreprocessor()
            row = pre.run_all(pd.DataFrame([safe_log]))
            row = row.tail(1).copy()

            # --- خطوة 3: حساب الـ Rolling Features (التتبع الزمني) ---
            rolling_features = get_rolling_features(
                ip     = safe_log["ip"],
                now    = now,
                status = int(row["status"].iloc[0]),
                path   = str(row["path_column"].iloc[0]),
                ext    = str(row["file_extension"].iloc[0]),
            )

            rolling_df = pd.DataFrame([rolling_features])
            row = pd.concat([row.reset_index(drop=True), rolling_df], axis=1)

            # --- خطوة 4: الـ PostSplit Alignment وتجهيز الأعمدة ---
            ip_freq = self.post["ip_freq"]
            referer_freq = self.post["referer_freq"]
            train_columns = self.post["train_columns"]

            df = row.copy()
            df["ip_frequency"] = df["ip"].map(ip_freq).fillna(0)
            df["referer_frequency"] = df["referer"].map(referer_freq).fillna(0)

            cols_to_drop = [
                'browser','browser_family_processed','browser_family',
                'request_method','request','ip','referer','country',
                'country_processed','file_extension','attack_type',
                'weekday','path_column','os_name', 'timestamp',
                'datetime', 'source_ip', 'client_ip' 
            ]

            df.drop(columns=cols_to_drop, inplace=True, errors='ignore')
            df.fillna(0, inplace=True)
            df = df.reindex(columns=train_columns, fill_value=0)
            
            # --- خطوة 5: التنبؤ الحصري باستخدام Isolation Forest ---
            pred, score = self._predict_if(df)
            
            return {
                "prediction": pred,
                "reconstruction_error": score  # الباك إند مستني المفتاح ده عشان يسجل السكور
            }

        except Exception as e:
            print(f"[ANOMALY PIPELINE CRITICAL ERROR]: {e}")
            return {"prediction": "Normal", "reconstruction_error": 0.0}

    def _predict_if(self, row):
        """🌟 الدالة المسؤولة عن فحص الريكوست جوه الـ Isolation Forest"""
        try:
            # 1. تحويل الداتا بنفس مقاييس التدريب
            x = self.scaler_if.transform(row)
            x = self.pca.transform(x)
            
            # 2. حساب السكور
            score = -self.if_model.decision_function(x)[0]
            
            # 3. جلب الـ Threshold الثابت من التدريب
            threshold = self.if_meta.get("threshold", 0.5) if isinstance(self.if_meta, dict) else float(self.if_meta)
            
            # 4. اتخاذ القرار وإرجاع (القرار، السكور) معاً لمنع الـ Crash القديم
            decision = "Attack" if score >= threshold else "Normal"
            
            return decision, float(score)
            
        except Exception as e:
            print(f"[IF PREDICT ERROR]: {e}")
            return "Normal", 0.0


# import joblib
# import numpy as np
# import pandas as pd
# import time
# import re 
# import os
# import json

# from anomaly.rolling import get_rolling_features
# from anomaly.preprocessing import PreSplitPreprocessor 

# class InferencePipeline:

#     def __init__(self):
#         base_path = os.path.dirname(os.path.abspath(__file__))
#         artifacts_path = os.path.join(base_path, "artifacts")
        
#         # Load preprocessing & scalers
#         self.post = joblib.load(os.path.join(artifacts_path, "postsplit.pkl"))
#         self.scaler_if = joblib.load(os.path.join(artifacts_path, "scaler_if.pkl"))
#         self.scaler_ae = joblib.load(os.path.join(artifacts_path, "scaler_ae.pkl"))
#         self.pca = joblib.load(os.path.join(artifacts_path, "pca_if.pkl"))

#         # Load models
#         self.if_model = joblib.load(os.path.join(artifacts_path, "isolation_forest.pkl"))
#         self.if_meta = joblib.load(os.path.join(artifacts_path, "if_metadata.pkl"))

#         self.ocsvm_model = joblib.load(os.path.join(artifacts_path, "ocsvm.pkl"))
#         self.ocsvm_meta = joblib.load(os.path.join(artifacts_path, "ocsvm_metadata.pkl"))

#         # import tensorflow as tf
#         # self.ae_model = tf.keras.models.load_model(os.path.join(artifacts_path, "autoencoder_model.keras")) 
#         # self.ae_meta = joblib.load(os.path.join(artifacts_path, "autoencoder_artifacts.pkl"))
#         # if isinstance(self.ae_meta, dict):
#         #     old_thresh = self.ae_meta.get("threshold", 0.65)
            
#         #     self.ae_meta.setdefault("mean", old_thresh * 0.5)  
#         #     self.ae_meta.setdefault("std", old_thresh * 0.17)  

#         import tensorflow as tf
#         self.ae_model = tf.keras.models.load_model(os.path.join(artifacts_path, "autoencoder_model.keras")) 
#         self.ae_meta = joblib.load(os.path.join(artifacts_path, "autoencoder_artifacts.pkl"))

#     # =========================================================
#     # MAIN PREDICT FUNCTION
#     # =========================================================
#     # =========================================================
#     # MAIN PREDICT FUNCTION (Smart Time & Debugging Version)
#     # =========================================================
#     # def predict(self, raw_log: dict, model_type: str = "ensemble"):
#     #     safe_log = raw_log.copy()

#     #     # 1️⃣ تحويل الوقت الذكي (الديناميكي) ليناسب المحاكاة، الرفع، والوقت الفعلي
#     #     log_time_str = safe_log.get("timestamp")
#     #     now = None

#     #     if log_time_str:
#     #         try:
#     #             log_time_str = str(log_time_str).replace("EDT", "").strip()
#     #             # المحاولة الأولى: لو التاريخ جاي بصيغة كالي الأصلية (Jun 24 2026 09:04:25)
#     #             if not "-" in log_time_str:
#     #                 from datetime import datetime
#     #                 # إزالة الأجزاء من الثانية لو وُجدت لتوحيد الصيغة
#     #                 base_time = log_time_str.split(".")[0]
#     #                 dt = datetime.strptime(base_time, "%b %d %Y %H:%M:%S")
#     #                 now = dt.timestamp()
#     #             else:
#     #                 # المحاولة الثانية: لو التاريخ جاي بصيغة ستاندرد (2026-06-24 09:04:25)
#     #                 from datetime import datetime
#     #                 base_time = log_time_str.split(".")[0]
#     #                 dt = datetime.strptime(base_time, "%Y-%m-%d %H:%M:%S")
#     #                 now = dt.timestamp()
#     #         except Exception as e:
#     #             # لو فشل الـ Parsing لأي صيغة غريبة، نتركها ليعود لوقت السيرفر
#     #             now = None

#     #     # Fallback: لو مفيش timestamp أو فشل التحويل، استخدم وقت السيرفر الحالي حالا (البيئة الحقيقية)
#     #     if now is None:
#     #         import time
#     #         now = time.time()

#     #     # بقية الكود كما هو لتأمين الـ IP والـ Status
#     #     if "ip" not in safe_log:
#     #         safe_log["ip"] = safe_log.get("source_ip", safe_log.get("client_ip", "127.0.0.1"))

#     #     raw_ip = str(safe_log.get("ip", "0.0.0.0")).strip()
#     #     clean_ip = raw_ip.split(":")[0] if ":" in raw_ip else raw_ip
#     #     safe_log["ip"] = clean_ip

#     #     if "status" not in safe_log: 
#     #         safe_log["status"] = 200

#     #     # STEP 1 — Preprocessing
#     #     pre = PreSplitPreprocessor()
#     #     row = pre.run_all(pd.DataFrame([safe_log]))
#     #     row = row.tail(1).copy()

#     #     # STEP 2 — Rolling (تم تمرير الـ now الذكي هنا)
#     #     rolling_features = get_rolling_features(
#     #         ip     = safe_log["ip"],
#     #         now    = now,
#     #         status = int(row["status"].iloc[0]),
#     #         path   = str(row["path_column"].iloc[0]),
#     #         ext    = str(row["file_extension"].iloc[0]),
#     #     )

#     #     rolling_df = pd.DataFrame([rolling_features])
#     #     row = pd.concat([row.reset_index(drop=True), rolling_df], axis=1)

#     #     # STEP 3 — PostSplit Encoding
#     #     ip_freq = self.post["ip_freq"]
#     #     referer_freq = self.post["referer_freq"]
#     #     train_columns = self.post["train_columns"]

#     #     df = row.copy()
#     #     df["ip_frequency"] = df["ip"].map(ip_freq).fillna(0)
#     #     df["referer_frequency"] = df["referer"].map(referer_freq).fillna(0)

#     #     cols_to_drop = [
#     #         'browser','browser_family_processed','browser_family',
#     #         'request_method','request','ip','referer','country',
#     #         'country_processed','file_extension','attack_type',
#     #         'weekday','path_column','os_name', 'timestamp'
#     #     ]

#     #     df.drop(columns=cols_to_drop, inplace=True, errors='ignore')
#     #     df.fillna(0, inplace=True)
#     #     df = df.reindex(columns=train_columns, fill_value=0)
#     #     row = df

#     #     # 2️⃣ طباعة الـ Vector المدخل للموديلات في الـ Terminal لرؤية الفيتشرز
#     #     print("\n" + "="*40)
#     #     print("--- INPUT VECTOR TO ANOMALY MODELS ---")
#     #     print(json.dumps(row.to_dict(orient='records')[0], indent=2))
#     #     print("="*40 + "\n")
        
#     #     # STEP 4 — Select model & Return structured data
#     #     if model_type == "ensemble":
#     #         # جلب النتيجة من الـ ensemble لطباعة الـ Debug قبل الـ return
#     #         final_result = self._predict_ensemble(row)
#     #         return final_result
#     #     elif model_type == "if":
#     #         pred, score = self._predict_if(row)
#     #         return {"prediction": pred, "reconstruction_error": score}
#     #     elif model_type == "ocsvm":
#     #         pred, score = self._predict_ocsvm(row)
#     #         return {"prediction": pred, "reconstruction_error": score}
#     #     elif model_type == "ae":
#     #         pred, error = self._predict_ae(row)
#     #         # تم تحريك الـ Print هنا لتعمل بشكل سليم وتظهر قيم الـ Autoencoder والـ Threshold
#     #         threshold = self.ae_meta["threshold"]
#     #         print(f" [DEBUG AE] -> Reconstruction Error: {error:.4f}, Threshold: {threshold:.4f}")
#     #         return {"prediction": pred, "reconstruction_error": error}
#     #     else:
#     #         raise ValueError("model_type must be: ensemble | if | ocsvm | ae")
   
#     def _predict_ensemble(self, row):
#         try:
#             # استدعاء الاسكورات من الموديلات الفرعية لعمل الـ Voting
#             _, if_score = self._predict_if(row)      
#             _, ocsvm_score = self._predict_ocsvm(row)  
#             _, ae_error = self._predict_ae(row)        

#             # 🌟 التعديل الإستراتيجي: التوقف عن حساب الـ Thresh من الترافيك المجهول الجديد
#             # واستخدام الـ Metadata الثابتة لبيانات التدريب النظيفة
#             if isinstance(self.ae_meta, dict) and "mean" in self.ae_meta and "std" in self.ae_meta:
#                 ae_thresh = self.ae_meta["mean"] + (3 * self.ae_meta["std"])
#             else:
#                 ae_thresh = 0.65 # القيمة الافتراضية الاحتياطية

#             if_thresh = 0.5
#             ocsvm_thresh = 0.5

#             # 🌟 تحويل القرارات لـ تصويت أغلبية (Majority Voting) بدل الأوزان الصارمة
#             votes = 0
#             if if_score > if_thresh: votes += 1
#             if ocsvm_score > ocsvm_thresh: votes += 1
#             if ae_error > ae_thresh: votes += 1

#             # لو موديلين من أصل 3 قالوا هجوم -> القرار القطعي هجوم (توازن هندسي رائع)
#             final_decision = "Attack" if votes >= 2 else "Normal"

#             return {
#                 "prediction": final_decision,
#                 "reconstruction_error": float(ae_error) 
#             }
#         except Exception as e:
#             return {"prediction": "Normal", "reconstruction_error": 0.0}
#     #  الأصح و ادتنى دقة 100% فى تحديد الهجوم و اللى جربتها يوم 27
#     # def predict(self, raw_log: dict, model_type: str = "ensemble"):
#     #     now = time.time()
#     #     safe_log = raw_log.copy()

#     #     if "ip" not in safe_log:
#     #         safe_log["ip"] = safe_log.get("source_ip", safe_log.get("client_ip", "127.0.0.1"))

#     #     raw_ip = str(safe_log.get("ip", "0.0.0.0")).strip()
#     #     clean_ip = raw_ip.split(":")[0] if ":" in raw_ip else raw_ip
#     #     safe_log["ip"] = clean_ip

#     #     if "status" not in safe_log: 
#     #         safe_log["status"] = 200

#     #     pre = PreSplitPreprocessor()
#     #     row = pre.run_all(pd.DataFrame([safe_log]))
#     #     row = row.tail(1).copy()

#     #     # STEP 2 — Rolling
#     #     rolling_features = get_rolling_features(
#     #         ip     = safe_log["ip"],
#     #         now    = now,
#     #         status = int(row["status"].iloc[0]),
#     #         path   = str(row["path_column"].iloc[0]),
#     #         ext    = str(row["file_extension"].iloc[0]),
#     #     )

#     #     rolling_df = pd.DataFrame([rolling_features])
#     #     row = pd.concat([row.reset_index(drop=True), rolling_df], axis=1)

#     #     # STEP 3 — PostSplit Encoding
#     #     ip_freq = self.post["ip_freq"]
#     #     referer_freq = self.post["referer_freq"]
#     #     train_columns = self.post["train_columns"]

#     #     df = row.copy()
#     #     df["ip_frequency"] = df["ip"].map(ip_freq).fillna(0)
#     #     df["referer_frequency"] = df["referer"].map(referer_freq).fillna(0)

#     #     cols_to_drop = [
#     #         'browser','browser_family_processed','browser_family',
#     #         'request_method','request','ip','referer','country',
#     #         'country_processed','file_extension','attack_type',
#     #         'weekday','path_column','os_name', 'timestamp'
#     #     ]

#     #     df.drop(columns=cols_to_drop, inplace=True, errors='ignore')
#     #     df.fillna(0, inplace=True)
#     #     df = df.reindex(columns=train_columns, fill_value=0)
#     #     row = df

#     #     print("--- INPUT VECTOR TO MODELS ---")
#     #     print(row.to_dict(orient='records')[0])

#     #     # STEP 4 — Select model & Return structured data
#     #     if model_type == "ensemble":
#     #         return self._predict_ensemble(row)
#     #     elif model_type == "if":
#     #         pred, score = self._predict_if(row)
#     #         return {"prediction": pred, "reconstruction_error": score}
#     #     elif model_type == "ocsvm":
#     #         pred, score = self._predict_ocsvm(row)
#     #         return {"prediction": pred, "reconstruction_error": score}
#     #     elif model_type == "ae":
#     #         pred, error = self._predict_ae(row)
#     #         return {"prediction": pred, "reconstruction_error": error}
#     #     else:
#     #         raise ValueError("model_type must be: ensemble | if | ocsvm | ae")
      
#     # =========================================================
#     # ENSEMBLE 
#     # =========================================================
#     # اخر نسخة يوم 27/6/2026 الساعى 12م
#     # def _predict_ensemble(self, row):
#     #     try:
#     #         # استدعاء الاسكورات من الموديلات الفرعية لعمل الـ Voting
#     #         _, if_score = self._predict_if(row)      
#     #         _, ocsvm_score = self._predict_ocsvm(row)  
#     #         _, ae_error = self._predict_ae(row)        

#     #         # 🌟 التعديل الإستراتيجي: التوقف عن حساب الـ Thresh من الترافيك المجهول الجديد
#     #         # واستخدام الـ Metadata الثابتة لبيانات التدريب النظيفة
#     #         if isinstance(self.ae_meta, dict) and "mean" in self.ae_meta and "std" in self.ae_meta:
#     #             ae_thresh = self.ae_meta["mean"] + (3 * self.ae_meta["std"])
#     #         else:
#     #             ae_thresh = 0.65 # القيمة الافتراضية الاحتياطية

#     #         if_thresh = 0.5
#     #         ocsvm_thresh = 0.5

#     #         # 🌟 تحويل القرارات لـ تصويت أغلبية (Majority Voting) بدل الأوزان الصارمة
#     #         votes = 0
#     #         if if_score > if_thresh: votes += 1
#     #         if ocsvm_score > ocsvm_thresh: votes += 1
#     #         if ae_error > ae_thresh: votes += 1

#     #         # لو موديلين من أصل 3 قالوا هجوم -> القرار القطعي هجوم (توازن هندسي رائع)
#     #         final_decision = "Attack" if votes >= 2 else "Normal"

#     #         return {
#     #             "prediction": final_decision,
#     #             "reconstruction_error": float(ae_error) 
#     #         }
#     #     except Exception as e:
#     #         return {"prediction": "Normal", "reconstruction_error": 0.0}

#     #  آخر نسخة قبل يوم 27
#     # def _predict_ensemble(self, row):
#     #     try:
#     #         _, if_score = self._predict_if(row)      
#     #         _, ocsvm_score = self._predict_ocsvm(row)  
#     #         _, ae_error = self._predict_ae(row)        

#     #         # 🌟 هنا التعديل: هنستخدم قيم الـ Mean/Std اللي الموديل اتدرب عليهم (وهي قيم ثابتة وموثوقة)
#     #         # بدل ما يحسب من الداتا الجديدة، هيستخدم الـ Metadata الأصلية
#     #         if isinstance(self.ae_meta, dict) and "mean" in self.ae_meta and "std" in self.ae_meta:
#     #             # الـ 3 هنا ثابتة، الموديل اتدرب على دي، خليها 3 زي ما هي
#     #             ae_thresh = self.ae_meta["mean"] + (3 * self.ae_meta["std"])
#     #         else:
#     #             ae_thresh = 0.65 # قيمة افتراضية لو الـ meta مش موجود

#     #         if_thresh = 0.5
#     #         ocsvm_thresh = 0.5

#     #         # Normalization
#     #         if_norm = if_score / if_thresh
#     #         ocsvm_norm = ocsvm_score / ocsvm_thresh
#     #         ae_norm = ae_error / ae_thresh

#     #         # قرار حازم
#     #         final_weighted_score = (ae_norm * 0.50) + (if_norm * 0.25) + (ocsvm_norm * 0.25)

#     #         return {
#     #             "prediction": "Attack" if final_weighted_score >= 1.0 else "Normal",
#     #             "reconstruction_error": float(ae_error) 
#     #         }
#     #     except Exception as e:
#     #         return {"prediction": "Normal", "reconstruction_error": 0.0}
#     # --------------------------------
#     # def _predict_ensemble(self, row):
#     #     try:
#     #         # 1. جلب السكورز الأصلية من الموديلات
#     #         _, if_score = self._predict_if(row)      
#     #         _, ocsvm_score = self._predict_ocsvm(row)  
#     #         _, ae_error = self._predict_ae(row)        

#     #         # 2. حساب الـ Thresholds (إما ديناميكياً أو Fallback آمن)
#     #         if_thresh = self.if_meta.get("threshold", 0.5) if isinstance(self.if_meta, dict) else float(self.if_meta)
#     #         ocsvm_thresh = self.ocsvm_meta.get("threshold", 0.5) if isinstance(self.ocsvm_meta, dict) else float(self.ocsvm_meta)

#     #         if isinstance(self.ae_meta, dict) and "mean" in self.ae_meta and "std" in self.ae_meta:
#     #             ae_thresh = self.ae_meta["mean"] + (3 * self.ae_meta["std"])
#     #         else:
#     #             ae_thresh = self.ae_meta.get("threshold", 0.65) if isinstance(self.ae_meta, dict) else float(self.ae_meta)

#     #         # تأمين منع القسمة على صفر
#     #         if_thresh = if_thresh if if_thresh != 0 else 0.5
#     #         ocsvm_thresh = ocsvm_thresh if ocsvm_thresh != 0 else 0.5
#     #         ae_thresh = ae_thresh if ae_thresh != 0 else 0.65

#     #         # 3. تحويل السكورز لنسب مئوية (Normalization)
#     #         if_norm = if_score / if_thresh
#     #         ocsvm_norm = ocsvm_score / ocsvm_thresh
#     #         ae_norm = ae_error / ae_thresh

#     #         # 4. حساب المتوسط الموزون (Weighted Score)
#     #         final_weighted_score = (ae_norm * 0.50) + (if_norm * 0.25) + (ocsvm_norm * 0.25)

#     #         if final_weighted_score >= 1.0:
#     #             final_decision = "Attack"
#     #         else:
#     #             final_decision = "Normal"

#     #         return {
#     #             "prediction": final_decision,
#     #             "reconstruction_error": float(ae_error) 
#     #         }

#     #     except Exception as e:
#     #         # Fallback لحماية الباك اند من الـ Crash أثناء التيست الشامل
#     #         print(f"[Ensemble Error Triggered Fallback]: {e}")
#     #         if_pred, _ = self._predict_if(row)
#     #         ocsvm_pred, _ = self._predict_ocsvm(row)
#     #         ae_pred, ae_error = self._predict_ae(row)
            
#     #         preds = [if_pred, ocsvm_pred, ae_pred]
#     #         attack_votes = sum(1 for p in preds if p == "Attack")
#     #         return {
#     #             "prediction": "Attack" if attack_votes >= 2 else "Normal",
#     #             "reconstruction_error": float(ae_error)
#     #         }
#     # الكود اللى ادانى دقة 69
#     # def _predict_ensemble(self, row):
#     #     # 1. جلب السكورز الأصلية من الموديلات
#     #     _, if_score = self._predict_if(row)      # سكور الـ Isolation Forest
#     #     _, ocsvm_score = self._predict_ocsvm(row)  # سكور الـ One-Class SVM
#     #     _, ae_error = self._predict_ae(row)        # سكور الـ Autoencoder

#     #     # 2. جلب الـ Thresholds المحفوظة جوه الـ Metadata
#     #     if_thresh = self.if_meta["threshold"]
#     #     ocsvm_thresh = self.ocsvm_meta["threshold"]
#     #     ae_thresh = self.ae_meta["threshold"]

#     #     # 3. تحويل السكورز لنسبة مئوية (قريبة من الـ Threshold بتاعه)
#     #     # لو النسبة أكبر من 1.0 معناه إن السكور عدى الـ Threshold بتاعه
#     #     if_norm = if_score / if_thresh if if_thresh != 0 else 0
#     #     ocsvm_norm = ocsvm_score / ocsvm_thresh if ocsvm_thresh != 0 else 0
#     #     ae_norm = ae_error / ae_thresh if ae_thresh != 0 else 0

#     #     # 4. حساب المتوسط الموزون (Weighted Score)
#     #     # بنعطي وزن أكبر للـ Autoencoder (مثلاً 50%) وبقية الموديلات (25% لكل واحد)
#     #     final_weighted_score = (ae_norm * 0.50) + (if_norm * 0.25) + (ocsvm_norm * 0.25)

#     #     # Decision Rule: لو المتوسط الموزون أكبر من 1.0 معناه الأغلبية أو القوة التصويتية مالية للهجوم
#     #     if final_weighted_score >= 1.0:
#     #         final_decision = "Attack"
#     #     else:
#     #         final_decision = "Normal"

#     #     return {
#     #         "prediction": final_decision,
#     #         "reconstruction_error": float(ae_error) 
#     #     }
#     # ===================================================
#     # الكود الأصلى
#     def _predict_ensemble(self, row):
#         if_pred, if_score = self._predict_if(row)
#         ocsvm_pred, ocsvm_score = self._predict_ocsvm(row)
#         ae_pred, ae_error = self._predict_ae(row)

#         preds = [if_pred, ocsvm_pred, ae_pred]
#         attack_votes = sum(1 for p in preds if p == "Attack")

#         final_decision = "Attack" if attack_votes >= 2 else "Normal"

#         return {
#             "prediction": final_decision,
#             "reconstruction_error": float(ae_error) 
#         }
      
#     def _predict_if(self, row):
#         x = self.scaler_if.transform(row)
#         x = self.pca.transform(x)
#         score = -self.if_model.decision_function(x)[0]
#         threshold = self.if_meta["threshold"]
#         return ("Attack" if score >= threshold else "Normal"), float(score)

#     def _predict_ocsvm(self, row):
#         x = self.scaler_if.transform(row)
#         x = self.pca.transform(x)
#         score = -self.ocsvm_model.decision_function(x)[0]
#         threshold = self.ocsvm_meta["threshold"]
#         return ("Attack" if score >= threshold else "Normal"), float(score)

#     def _predict_ae(self, row):
#         x = self.scaler_ae.transform(row)
#         recon = self.ae_model.predict(x, verbose=0)
#         error = np.mean(np.abs(x - recon), axis=1)[0]
#         threshold = self.ae_meta["threshold"]
#         print(f"[LIVE AE CHECK] -> Error: {error:.5f} | Threshold: {threshold:.5f} -> Prediction: {'Attack' if error >= threshold else 'Normal'}")
#         return ("Attack" if error >= threshold else "Normal"), float(error)
    

# # import joblib
# # import numpy as np
# # import pandas as pd
# # import time
# # import re 

# # from anomaly.rolling import get_rolling_features
# # from anomaly.preprocessing import PreSplitPreprocessor
# # import os

# # class InferencePipeline:

# #     def __init__(self):
# #         base_path = os.path.dirname(os.path.abspath(__file__))
# #         artifacts_path = os.path.join(base_path, "artifacts")
# #         # -----------------------------
# #         # Load preprocessing
# #         # -----------------------------
# #         self.post = joblib.load(os.path.join(artifacts_path, "postsplit.pkl"))
# #         self.scaler_if = joblib.load(os.path.join(artifacts_path, "scaler_if.pkl"))
# #         self.scaler_ae = joblib.load(os.path.join(artifacts_path, "scaler_ae.pkl"))
# #         self.pca = joblib.load(os.path.join(artifacts_path, "pca_if.pkl"))

# #         # -----------------------------
# #         # Load models
# #         # -----------------------------
# #         self.if_model = joblib.load(os.path.join(artifacts_path, "isolation_forest.pkl"))
# #         self.if_meta = joblib.load(os.path.join(artifacts_path, "if_metadata.pkl"))

# #         self.ocsvm_model = joblib.load(os.path.join(artifacts_path, "ocsvm.pkl"))
# #         self.ocsvm_meta = joblib.load(os.path.join(artifacts_path, "ocsvm_metadata.pkl"))

# #         import tensorflow as tf
# #         self.ae_model = tf.keras.models.load_model(os.path.join(artifacts_path, "autoencoder_model.keras")) 
# #         self.ae_meta = joblib.load(os.path.join(artifacts_path, "autoencoder_artifacts.pkl"))

# #     # =========================================================
# #     # MAIN PREDICT FUNCTION (backend calls ONLY this)
# #     # =========================================================
# #     def predict(self, raw_log: dict, model_type: str = "ensemble"):

# #         now = time.time()
# #         safe_log = raw_log.copy()

# #         # -------------------------------------------------
# #         # STEP 1 — IP Cleaning & Mapping
# #         # -------------------------------------------------
# #         # التأكد من وجود مفتاح ip وتوحيده
# #         if "ip" not in safe_log:
# #             safe_log["ip"] = safe_log.get("source_ip", safe_log.get("client_ip", "127.0.0.1"))

# #         # تنظيف الـ IP من المسافات أو البورت
# #         raw_ip = str(safe_log.get("ip", "0.0.0.0")).strip()
# #         if ":" in raw_ip:
# #             clean_ip = raw_ip.split(":")[0]
# #         else:
# #             clean_ip = raw_ip
        
# #         safe_log["ip"] = clean_ip

# #         print(f"DEBUG: Processing IP: '{safe_log['ip']}' | Keys in safe_log: {list(safe_log.keys())}")
        
# #         # -------------------------------------------------

# #         if "status" not in safe_log: safe_log["status"] = 200

# #         pre = PreSplitPreprocessor()
# #         row = pre.run_all(pd.DataFrame([safe_log]))

# #         # take latest row
# #         row = row.tail(1).copy()
# #         # -------------------------------------------------
# #         # STEP 2 — Rolling (Redis-based)
# #         # -------------------------------------------------

# #         rolling_features = get_rolling_features(
# #             ip     = safe_log["ip"],
# #             now    = now,
# #             status = int(row["status"].iloc[0]),
# #             path   = str(row["path_column"].iloc[0]),
# #             ext    = str(row["file_extension"].iloc[0]),
# #         )

# #         # convert to dataframe for safe merge
# #         rolling_df = pd.DataFrame([rolling_features])

# #         # MERGE
# #         row = pd.concat([row.reset_index(drop=True), rolling_df], axis=1)

# #         # -------------------------------------------------
# #         # STEP 3 — PostSplit (learned encoding)
# #         # -------------------------------------------------
# #         ip_freq = self.post["ip_freq"]
# #         referer_freq = self.post["referer_freq"]
# #         train_columns = self.post["train_columns"]

# #         df = row.copy()

# #         df["ip_frequency"] = df["ip"].map(ip_freq).fillna(0)
# #         df["referer_frequency"] = df["referer"].map(referer_freq).fillna(0)

# #         cols_to_drop = [
# #             'browser','browser_family_processed','browser_family',
# #             'request_method','request','ip','referer','country',
# #             'country_processed','file_extension','attack_type',
# #             'weekday','path_column','os_name', 'timestamp'
# #         ]

# #         df.drop(columns=cols_to_drop, inplace=True, errors='ignore')
# #         df.fillna(0, inplace=True)

# #         # ALIGNMENT (VERY IMPORTANT)
# #         df = df.reindex(columns=train_columns, fill_value=0)

# #         row = df


# #         # -------------------------------------------------
# #         # STEP 4 — Select model
# #         # -------------------------------------------------
# #         if model_type == "ensemble":
# #             return self._predict_ensemble(row)

# #         elif model_type == "if":
# #             return self._predict_if(row)

# #         elif model_type == "ocsvm":
# #             return self._predict_ocsvm(row)

# #         elif model_type == "ae":
# #             return self._predict_ae(row)

# #         else:
# #             raise ValueError("model_type must be: ensemble | if | ocsvm | ae")
        

# #     # =========================================================
# #     # ENSEMBLE (Anomaly Detection)
# #     # =========================================================
# #     def _predict_ensemble(self, row):

# #         models = [
# #             ("if", self._predict_if),
# #             ("ocsvm", self._predict_ocsvm),
# #             ("ae", self._predict_ae)
# #         ]
# #         preds = []

# #         # Get predictions from all models
# #         for name, func in models:
# #             preds.append(func(row))   # "Attack" or "Normal"

# #         # Count votes
# #         attack_votes = sum(1 for p in preds if p == "Attack")

# #         # Decision rule (2-out-of-3)
# #         if attack_votes >= 2:
# #             final = "Attack"
# #         else:
# #             final = "Normal"


# #         return {"prediction": final}
      
# #     # =========================================================
# #     # ISOLATION FOREST
# #     # =========================================================
# #     def _predict_if(self, row):

# #         x = self.scaler_if.transform(row)
# #         x = self.pca.transform(x)

# #         score = -self.if_model.decision_function(x)[0]
# #         threshold = self.if_meta["threshold"]

# #         return ("Attack" if int(score >= threshold) else "Normal")

# #     # =========================================================
# #     # OCSVM
# #     # =========================================================
# #     def _predict_ocsvm(self, row):

# #         x = self.scaler_if.transform(row)
# #         x = self.pca.transform(x)

# #         score = -self.ocsvm_model.decision_function(x)[0]
# #         threshold = self.ocsvm_meta["threshold"]

# #         return ("Attack" if int(score >= threshold) else "Normal")

# #     # =========================================================
# #     # AUTOENCODER
# #     # =========================================================
# #     def _predict_ae(self, row):

# #         x = self.scaler_ae.transform(row)

# #         recon = self.ae_model.predict(x, verbose=0)
# #         error = np.mean(np.abs(x - recon), axis=1)[0]

# #         threshold = self.ae_meta["threshold"]

# #         return ("Attack" if int(error >= threshold) else "Normal")


    