import numpy as np
import pandas as pd
import math
import re
from collections import Counter

class PreSplitPreprocessor:

    def __init__(self):
        pass

    # -----------------------------
    # 0) Normalize Input (SUPER FIXED)
    # -----------------------------
    def normalize_input(self, df):
        new_df = pd.DataFrame(index=df.index)
        
   
        def get_first_existing(cols, default_val):
            for col in cols:
                if col in df.columns:
                    return df[col]
            return pd.Series([default_val] * len(df), index=df.index)

        new_df['ip'] = get_first_existing(['ip', 'source_ip', 'client_ip', 'remote_addr'], '127.0.0.1')
        new_df['datetime'] = get_first_existing(['timestamp', 'datetime', 'time'], None)
        new_df['request'] = get_first_existing(['request', 'request_url', 'url', 'uri'], '/')
        new_df['status'] = get_first_existing(['status', 'status_code'], 200)
        new_df['size'] = get_first_existing(['size', 'response_size'], 0)
        new_df['referer'] = get_first_existing(['referer', 'referrer'], '-')
        new_df['browser'] = get_first_existing(['browser', 'user_agent', 'agent'], 'unknown')

        new_df['status'] = pd.to_numeric(new_df['status'], errors='coerce').fillna(200)
        
        return new_df

    # -----------------------------
    # 1) Handle missing values & duplicates
    # -----------------------------
    def handle_missing_values(self, df):
        df = df.copy()

        df.drop_duplicates(inplace=True)
        df.reset_index(drop=True, inplace=True)
        
        df['size_str'] = df['size'].astype(str)
        mask_non_numeric = ~df['size_str'].str.isnumeric()
        df.loc[mask_non_numeric & df['browser'].isna(), 'browser'] = df.loc[mask_non_numeric & df['browser'].isna(), 'size_str']
        df.loc[mask_non_numeric, 'size'] = np.nan
        df['size'] = pd.to_numeric(df['size'], errors='coerce')
        df.drop(columns=['size_str'], inplace=True)
        
        df['request'] = df['request'].replace('-', np.nan).fillna('EMPTY')
        df['referer'] = df['referer'].replace('-', np.nan).fillna('Unknown')
        df['browser'] = df['browser'].replace('-', np.nan).fillna('Unknown')
        df['size'] = df['size'].fillna(0)
        df['status'] = df['status'].fillna(200)
        return df

    # -----------------------------
    # 2) Timestamp parsing (FIXED)
    # -----------------------------
    def parse_timestamp(self, df):
        df = df.copy()

        gmt_hour = 7

        df['timestamp'] = pd.to_datetime(df['datetime'], errors='coerce')
        df['timestamp'] = df['timestamp'] + pd.to_timedelta(gmt_hour, unit='h')
        
        df.sort_values(['ip', 'timestamp'], inplace=True)
        df['hour'] = df['timestamp'].dt.hour
        df['weekday'] = df['timestamp'].dt.weekday
        df['is_weekend'] = df['weekday'].isin([5, 6]).astype(int)
        return df

    # -----------------------------
    # 6) Request Parsing
    # -----------------------------
    def parse_request(self, df):

        df = df.copy()

        request_split = df['request'].str.split(' ', n=1, expand=True)

        if request_split.shape[1] >= 2:
            df['path_column'] = request_split[1].fillna('')
        else:
            df['path_column'] = df['request'].fillna('')

        path_col = df['path_column']

        path_only = path_col.str.split('?', n=1, expand=True)[0].fillna('')

        df['path_length'] = path_col.apply(len)
        df['url_depth'] = path_only.str.count('/')
        df['has_query'] = path_col.str.contains(r'\?', regex=True).astype(int)
     
        def extract_ext(path):
            match = re.search(r'\.([a-zA-Z0-9]+)$', path)
            return match.group(1).lower() if match else 'no_ext'

        df['file_extension'] = path_only.apply(extract_ext).astype('category')
        
        suspicious_chars = r'[<>\"\'\(\);]'
        df['susp_char_count'] = path_col.str.count(suspicious_chars).fillna(0)
        df['susp_char_ratio'] = (df['susp_char_count'] / (df['path_length'] + 1e-6)).fillna(0)
        
        df['has_double_extension'] = path_only.apply(lambda x: 1 if x.split('/')[-1].count('.') > 1 else 0)
        df.drop(columns=['susp_char_count'], inplace=True, errors='ignore')
        return df

    # -----------------------------
    # 8) Browser & OS Features
    # -----------------------------
    def extract_browser_os(self, df):
        df = df.copy()

        ua_series = df['browser'].astype(str)

        df['ua_length'] = ua_series.apply(len)
        df['ua_entropy'] = ua_series.apply(self.calculate_entropy)
        df['ua_separator_count'] = ua_series.str.count(r'[;()]')
        df['is_ua_missing_mozilla'] = (~ua_series.str.lower().str.startswith('mozilla/')).astype(int)

        conformance_pattern = r'AppleWebKit\/[0-9\.]+\s+\(KHTML\s*,\s*like\s*Gecko\)'
        df['is_ua_malformed_struct'] = (
            ~ua_series.str.contains(conformance_pattern, case=False, regex=True).fillna(False)
        ).astype(int)

        df['os_temp'] = df['browser'].str.extract(r'\((.*?)\)')
        df['os_name'] = (
            df['os_temp']
            .fillna('Unknown_OS')
            .astype(str)
            .str.split(';').str[0]
            .str.split(',').str[0]
            .str.strip()
        )

        df['os_name'] = df['os_name'].replace({
            'Windows NT 10.0': 'Windows 10',
            'Linux; Android': 'Android',
            'Macintosh; Intel Mac OS X': 'MacOS'
        })

        def extract_browser(ua_string):
            ua_string = ua_string.lower()
            if 'chrome' in ua_string and 'safari' in ua_string: return 'Chrome'
            if 'firefox' in ua_string: return 'Firefox'
            if 'safari' in ua_string: return 'Safari'
            if 'edge' in ua_string: return 'Edge'
            if 'trident' in ua_string: return 'IE'
            if any(b in ua_string for b in ['bot','crawler','spider']):
                return 'Web_Bot_Script'
            return 'Other_Tool'

        df['browser_family'] = df['browser'].apply(extract_browser)

        df['is_outdated_windows_browser'] = (
            df['os_name'].str.contains('Windows', case=False) &
            df['browser_family'].isin(['IE', 'Other_Tool'])
        ).astype(int)

        df.drop(columns=['os_temp'], inplace=True, errors='ignore')

        return df

    # -----------------------------
    # 9) Entropy utility
    # -----------------------------
    @staticmethod
    def calculate_entropy(text):
        if not text:
            return 0.0

        counts = Counter(text)
        probs = [c / len(text) for c in counts.values()]
        return -sum(p * math.log2(p) for p in probs)

    def compute_entropy(self, df):
        df = df.copy()
        df['url_entropy'] = df['path_column'].apply(self.calculate_entropy)
        return df

    # -----------------------------
    # 10) Select model features (NEW)
    # -----------------------------
    def select_model_features(self, df):
        df = df.copy()

        features = [
            'hour', 'weekday', 'is_weekend',
            'path_length', 'url_depth', 'has_query',
            'susp_char_ratio', 'has_double_extension',
            'ua_length', 'ua_entropy',
            'is_ua_missing_mozilla',
            'is_ua_malformed_struct',
            'is_outdated_windows_browser',
            'url_entropy'
        ]

        for col in features:
            if col not in df.columns:
                df[col] = 0

        return df[features]

    # -----------------------------
    # 11) Full pipeline (UPDATED)
    # -----------------------------
    def run_all(self, df):
        df = self.normalize_input(df)
        df = self.handle_missing_values(df)
        df = self.parse_timestamp(df)
        df = self.parse_request(df)
        df = self.extract_browser_os(df)
        df = self.compute_entropy(df)

        return df

# import numpy as np
# import pandas as pd
# import math
# import re
# from collections import Counter

# class PreSplitPreprocessor:

#     def __init__(self):
#         pass

#     # -----------------------------
#     # 0) Normalize Input (NEW)
#     # -----------------------------
#     def normalize_input(self, df):
#         df = df.copy()

#         rename_map = {
#             'client_ip': 'ip',
#             'remote_addr': 'ip',
#             'user_agent': 'browser',
#             'agent': 'browser',
#             'url': 'request',
#             'uri': 'request',
#             'time': 'datetime',
#             'timestamp': 'datetime'
#         }

#         df = df.rename(columns=rename_map)

#         required_cols = [
#             'ip', 'datetime', 'request',
#             'status', 'size', 'referer', 'browser'
#         ]

#         for col in required_cols:
#             if col not in df.columns:
#                 df[col] = None
#         if 'status' not in df.columns:
#           df['status'] = 200

#         df['status'] = pd.to_numeric(df['status'], errors='coerce').fillna(200)

#         return df.reindex(columns=required_cols)
#         # return df[required_cols]

#     # -----------------------------
#     # 1) Handle missing values & duplicates
#     # -----------------------------
#     def handle_missing_values(self, df):
#         df = df.copy()

#         df.drop_duplicates(inplace=True)
#         df.reset_index(drop=True, inplace=True)
        
#         df['size_str'] = df['size'].astype(str)
#         mask_non_numeric = ~df['size_str'].str.isnumeric()

#         df.loc[mask_non_numeric & df['browser'].isna(), 'browser'] = \
#             df.loc[mask_non_numeric & df['browser'].isna(), 'size_str']

#         df.loc[mask_non_numeric, 'size'] = np.nan
#         df['size'] = pd.to_numeric(df['size'], errors='coerce')

#         df.drop(columns=['size_str'], inplace=True)
        
#         df['request'] = df['request'].replace('-', np.nan).fillna('EMPTY')
#         df['referer'] = df['referer'].replace('-', np.nan).fillna('Unknown')
#         df['browser'] = df['browser'].replace('-', np.nan).fillna('Unknown')
#         df['size'] = df['size'].replace('-', np.nan).fillna(0)
#         df['status'] = df['status'].replace('-', np.nan).fillna(0)

#         return df

#     # -----------------------------
#     # 2) Timestamp parsing (FIXED)
#     # -----------------------------
#     def parse_timestamp(self, df):
#         df = df.copy()

#         df['timestamp'] = pd.to_datetime(df['datetime'], errors='coerce')

#         df.drop(columns=['datetime'], inplace=True, errors='ignore')

#         df.sort_values(['ip', 'timestamp'], inplace=True)

#         df['hour'] = df['timestamp'].dt.hour
#         df['weekday'] = df['timestamp'].dt.weekday
#         df['is_weekend'] = df['weekday'].isin([5, 6]).astype(int)

#         return df

#     # -----------------------------
#     # 6) Request Parsing
#     # -----------------------------
#     def parse_request(self, df):

#         df = df.copy()

#         # 1. تقسيم الريكويست مع تحديد عدد الأعمدة المتوقع (2 أعمدة: Method و Path)
#         request_split = df['request'].str.split(' ', n=1, expand=True)

#         # 2. معالجة حالة الريكويستات الـ Malformed (لو الريكويست كلمة واحدة مفيهاش مسافة)
#         if request_split.shape[1] < 2:
#             # لو التقسيم فشل، بنخلي الـ Method هي الريكويست نفسه والـ Path فاضي
#             df['method'] = df['request']
#             df['path_column'] = ""
#         else:
#             df['method'] = request_split[0].fillna('GET') # افتراضي GET لو فاضي
#             df['path_column'] = request_split[1].fillna('')

#         # التصحيح: استعملي العمود اللي ضفتيه للـ df عشان تضمني وجوده
#         # بدلاً من مناداة request_split[1] مباشرة
#         path_col_series = df['path_column']

#         # 3. استخراج الـ Path بدون Query Params (للتحليل الأدق)
#         path_only = path_col_series.str.split('?', n=1, expand=True)[0].fillna('')

#         # 4. حساب الـ Features اللي الموديل بيحتاجها
#         df['path_length'] = path_col_series.apply(len)
#         df['url_depth'] = path_only.str.count('/')
#         df['has_query'] = path_col_series.str.contains(r'\?', regex=True).astype(int)
     
#         # 5. استخراج الامتداد (Extract Extension)
#         def extract_ext(path):
#             if not path: return 'no_ext'
#             # path_only_local = path.split('?', 1)[0] # مش محتاجة دي لأنك باعتة path_only أصلاً
#             match = re.search(r'\.([a-zA-Z0-9]+)$', path)
#             return match.group(1).lower() if match else 'no_ext'

#         df['file_extension'] = path_only.apply(extract_ext).astype('category')

#         # 6. الرموز المشبوهة (Suspicious Chars)
#         suspicious_chars = r'[<>\"\'\(\);]'
#         # لازم نستخدم الـ Series اللي فيها المسار الكامل (path_col_series)
#         df['susp_char_count'] = path_col_series.str.count(suspicious_chars).fillna(0)

#         df['susp_char_ratio'] = (
#             df['susp_char_count'] / (df['path_length'] + 1e-6)
#         ).fillna(0)

#         # تنظيف الأعمدة المؤقتة
#         df.drop(columns=['susp_char_count'], inplace=True, errors='ignore')

#         # 7. فحص الامتداد المزدوج (Double Extension)
#         df['has_double_extension'] = path_only.apply(
#             lambda x: 1 if x.split('/')[-1].count('.') > 1 else 0
#         )

#         return df
    
#         # request_split = df['request'].str.split(' ', n=2, expand=True)
       
#         # # if request_split.shape[1] > 1:
#         # #     path_column = request_split[1].fillna('')
#         # # else:
#         # #     df['path_column'] = df['request'].fillna('')
        
#         # # path_only = df['path_column'].str.split('?', n=1, expand=True)[0]       
#         # path_column = request_split[1].fillna('')
#         # df['path_column'] = path_column

#         # path_only = path_column.str.split('?', n=1, expand=True)[0]

#         # df['path_length'] = path_column.apply(len)
#         # df['url_depth'] = path_only.str.count('/')
#         # df['has_query'] = path_column.str.contains(r'\?', regex=True).astype(int)

#         # def extract_ext(path):
#         #     path_only_local = path.split('?', 1)[0]
#         #     match = re.search(r'\.([a-zA-Z0-9]+)$', path_only_local)
#         #     return match.group(1).lower() if match else 'no_ext'

#         # df['file_extension'] = path_only.apply(extract_ext).astype('category')

#         # suspicious_chars = r'[<>\"\'\(\);]'
#         # df['susp_char_count'] = path_column.str.count(suspicious_chars)

#         # df['susp_char_ratio'] = (
#         #     df['susp_char_count'] / (df['path_length'] + 1e-6)
#         # ).fillna(0)

#         # df.drop(columns=['susp_char_count'], inplace=True, errors='ignore')

#         # df['dot_count_in_filename'] = path_only.apply(
#         #     lambda x: x.split('/')[-1].count('.')
#         # )

#         # df['has_double_extension'] = (df['dot_count_in_filename'] > 1).astype(int)

#         # df.drop(columns=['dot_count_in_filename'], inplace=True, errors='ignore')

#         # return df

#     # -----------------------------
#     # 8) Browser & OS Features
#     # -----------------------------
#     def extract_browser_os(self, df):
#         df = df.copy()

#         ua_series = df['browser'].astype(str)

#         df['ua_length'] = ua_series.apply(len)
#         df['ua_entropy'] = ua_series.apply(self.calculate_entropy)
#         df['ua_separator_count'] = ua_series.str.count(r'[;()]')
#         df['is_ua_missing_mozilla'] = (~ua_series.str.lower().str.startswith('mozilla/')).astype(int)

#         conformance_pattern = r'AppleWebKit\/[0-9\.]+\s+\(KHTML\s*,\s*like\s*Gecko\)'
#         df['is_ua_malformed_struct'] = (
#             ~ua_series.str.contains(conformance_pattern, case=False, regex=True).fillna(False)
#         ).astype(int)

#         df['os_temp'] = df['browser'].str.extract(r'\((.*?)\)')
#         df['os_name'] = (
#             df['os_temp']
#             .fillna('Unknown_OS')
#             .astype(str)
#             .str.split(';').str[0]
#             .str.split(',').str[0]
#             .str.strip()
#         )

#         df['os_name'] = df['os_name'].replace({
#             'Windows NT 10.0': 'Windows 10',
#             'Linux; Android': 'Android',
#             'Macintosh; Intel Mac OS X': 'MacOS'
#         })

#         def extract_browser(ua_string):
#             ua_string = ua_string.lower()
#             if 'chrome' in ua_string and 'safari' in ua_string: return 'Chrome'
#             if 'firefox' in ua_string: return 'Firefox'
#             if 'safari' in ua_string: return 'Safari'
#             if 'edge' in ua_string: return 'Edge'
#             if 'trident' in ua_string: return 'IE'
#             if any(b in ua_string for b in ['bot','crawler','spider']):
#                 return 'Web_Bot_Script'
#             return 'Other_Tool'

#         df['browser_family'] = df['browser'].apply(extract_browser)

#         df['is_outdated_windows_browser'] = (
#             df['os_name'].str.contains('Windows', case=False) &
#             df['browser_family'].isin(['IE', 'Other_Tool'])
#         ).astype(int)

#         df.drop(columns=['os_temp'], inplace=True, errors='ignore')

#         return df

#     # -----------------------------
#     # 9) Entropy utility
#     # -----------------------------
#     @staticmethod
#     def calculate_entropy(text):
#         if not text:
#             return 0.0

#         counts = Counter(text)
#         probs = [c / len(text) for c in counts.values()]
#         return -sum(p * math.log2(p) for p in probs)

#     def compute_entropy(self, df):
#         df = df.copy()
#         df['url_entropy'] = df['path_column'].apply(self.calculate_entropy)
#         return df

#     # -----------------------------
#     # 10) Select model features (NEW)
#     # -----------------------------
#     def select_model_features(self, df):
#         df = df.copy()

#         features = [
#             'hour', 'weekday', 'is_weekend',
#             'path_length', 'url_depth', 'has_query',
#             'susp_char_ratio', 'has_double_extension',
#             'ua_length', 'ua_entropy',
#             'is_ua_missing_mozilla',
#             'is_ua_malformed_struct',
#             'is_outdated_windows_browser',
#             'url_entropy'
#         ]

#         for col in features:
#             if col not in df.columns:
#                 df[col] = 0

#         return df[features]

#     # -----------------------------
#     # 11) Full pipeline (UPDATED)
#     # -----------------------------
#     def run_all(self, df):
#         df = self.normalize_input(df)
#         df = self.handle_missing_values(df)
#         df = self.parse_timestamp(df)
#         df = self.parse_request(df)
#         df = self.extract_browser_os(df)
#         df = self.compute_entropy(df)
#         df = self.select_model_features(df)

#         return df
