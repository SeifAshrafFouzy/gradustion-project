from inference_pipline import InferencePipeline

pipeline = InferencePipeline()

#Normal
raw_log = {
    "ip": "36.79.86.26",
    "datetime": "2019-07-23 17:12",
    "gmt": 700,
    "request": "POST /bkd_baru/dosen/input_dosen/ HTTP/1.1",
    "status": 200,
    "size":2294,
    "referer": "http://universitas.com/bkd_baru/bidang_pendidikan",
    "browser": "Mozilla/5.0 (Windows NT 6.1; rv:60.0) Firefox/60.0",
    "country": "Indonesia"
}

#Attack
# raw_log = {
#     "ip": "171.25.193.91",
#     "datetime": "7/1/2019 1:49",
#     "gmt": 700,
#     "request": "GET /bkd_baru/system/run?command=ls& net user HTTP/1.1",
#     "status": 500,
#     "size":1439,
#     "referer": "-",
#     "browser": "Havij",
#     "country": "Iran"
# }

print("ensemble:", pipeline.predict(raw_log))

# print("IF:", pipeline.predict(raw_log, model_type="if"))
# print("OCSVM:", pipeline.predict(raw_log, model_type="ocsvm"))
# print("AE:", pipeline.predict(raw_log, model_type="ae"))
