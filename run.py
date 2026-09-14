import os
import subprocess
import sys
import time

def run_system():
    # 1. تشغيل الـ API من مجلد api
    # api_process = subprocess.Popen([
    #     sys.executable, "-m", "uvicorn", "api.main_api:app", "--host", "0.0.0.0", "--port", "8000"
    # ])
    CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
    env = os.environ.copy()
    env["PYTHONPATH"] = CURRENT_DIR
    print(f"Project Root Path: {CURRENT_DIR}")
    print("Starting FastAPI (Uvicorn)...")

    api_process = subprocess.Popen([
    sys.executable,
    "-m",
    "uvicorn",
    "api.main_api:combined_app",
    "--host",
    "0.0.0.0",
    "--port",
    "8000"
], env=env)
    # ننتظر ثواني نتأكد إن الـ API قام
    time.sleep(4)

    print("Starting RabbitMQ Consumer...")

    # 2. تشغيل الـ Consumer من مجلد data
    consumer_process = subprocess.Popen([
        sys.executable, "-m", "data.consumer"
    ], env=env)

    try:
        api_process.wait()
        consumer_process.wait()
    except KeyboardInterrupt:
        print("Stopping all processes...")
        api_process.terminate()
        consumer_process.terminate()

if __name__ == "__main__":
    run_system()
# import subprocess
# import threading


# def run_api():
#     subprocess.run(["uvicorn", "api.main_api:app"])


# def run_consumer():
#     subprocess.run(["python", "data.consumer.py"])


# if __name__ == "__main__":

#     t1 = threading.Thread(target=run_api)
#     t2 = threading.Thread(target=run_consumer)

#     t1.start()
#     t2.start()

#     t1.join()
#     t2.join()