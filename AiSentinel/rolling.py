import time
import uuid

# -----------------------------
# Redis Connection (singleton style)
# -----------------------------
from core.redis_client import redis_client as r
    
# -----------------------------
# Rolling Feature Function
# -----------------------------
def get_rolling_features(ip: str, now: float, status: int, path: str, ext: str):
    # -----------------------------
    # fallback لو Redis مش شغال
    # -----------------------------
    if r is None:
        return {
            "requests_last_1min": 0,
            "requests_last_5min": 0,
            "requests_last_10min": 0,
            "requests_last_15min": 0,

            "error_ratio_1min": 0,
            "error_ratio_5min": 0,
            "error_ratio_10min": 0,
            "error_ratio_15min": 0,

            "unique_paths_1min": 0,
            "unique_paths_5min": 0,
            "unique_paths_10min": 0,
            "unique_paths_15min": 0,

            "unique_ext_count_1min": 0,
            "unique_ext_count_5min": 0,
            "unique_ext_count_15min": 0,

            "unique_status_count_1min": 0,
            "unique_status_count_5min": 0,
            "unique_status_count_15min": 0,

            "time_diff_prev_request": 0,
        }
    
    ts_key     = f"ts:{ip}"
    err_key    = f"err:{ip}"
    path_key   = f"path:{ip}"
    ext_key    = f"ext:{ip}"
    status_key = f"status:{ip}"

    cutoff = now - 900  # 15 minutes window
    # member = str(now)
    unique_id = uuid.uuid4().hex[:8]
    member = f"{now}_{unique_id}"

    # -----------------------------
    # 1. Store current request
    # -----------------------------
    # r.zadd(ts_key, {member: now})
    # r.zadd(path_key,   {f"{path}||{now}": now})
    # r.zadd(ext_key,    {f"{ext}||{now}": now})
    # r.zadd(status_key, {f"{status}||{now}": now})

    # if status >= 400:
    #     r.zadd(err_key, {member: now})
    r.zadd(ts_key, {member: now})
    r.zadd(path_key,   {f"{path}||{member}": now})
    r.zadd(ext_key,    {f"{ext}||{member}": now})
    r.zadd(status_key, {f"{status}||{member}": now})

    if status >= 400:
        r.zadd(err_key, {member: now})

    # -----------------------------
    # 2. Cleanup old data (sliding window)
    # -----------------------------
    for key in [ts_key, err_key, path_key, ext_key, status_key]:
        r.zremrangebyscore(key, 0, cutoff)
        r.expire(key, 900)

    # -----------------------------
    # 3. Helper functions
    # -----------------------------
    def count(key, seconds):
        return r.zcount(key, now - seconds, now)

    def unique_count(key, seconds):
        members = r.zrangebyscore(key, now - seconds, now)
        values = [m.split("||")[0] for m in members]
        return len(set(values))

    # -----------------------------
    # 4. Request counts
    # -----------------------------
    req_1  = count(ts_key, 60)
    req_5  = count(ts_key, 300)
    req_10 = count(ts_key, 600)
    req_15 = count(ts_key, 900)

    # -----------------------------
    # 5. Error ratios
    # -----------------------------
    err_1  = count(err_key, 60)
    err_5  = count(err_key, 300)
    err_10 = count(err_key, 600)
    err_15 = count(err_key, 900)

    # -----------------------------
    # 6. Unique paths
    # -----------------------------
    u_path_1  = unique_count(path_key, 60)
    u_path_5  = unique_count(path_key, 300)
    u_path_10 = unique_count(path_key, 600)
    u_path_15 = unique_count(path_key, 900)

    # -----------------------------
    # 7. Unique extensions
    # -----------------------------
    u_ext_1  = unique_count(ext_key, 60)
    u_ext_5  = unique_count(ext_key, 300)
    u_ext_15 = unique_count(ext_key, 900)

    # -----------------------------
    # 8. Unique status codes
    # -----------------------------
    u_status_1  = unique_count(status_key, 60)
    u_status_5  = unique_count(status_key, 300)
    u_status_15 = unique_count(status_key, 900)

    # -----------------------------
    # 9. Time diff between last 2 requests
    # -----------------------------
    last_two = r.zrange(ts_key, -2, -1, withscores=True)
    time_diff = (last_two[-1][1] - last_two[-2][1]) if len(last_two) >= 2 else 0

    # -----------------------------
    # FINAL OUTPUT FEATURES
    # -----------------------------
    return {
        "requests_last_1min": req_1,
        "requests_last_5min": req_5,
        "requests_last_10min": req_10,
        "requests_last_15min": req_15,

        "error_ratio_1min": err_1 / req_1 if req_1 else 0,
        "error_ratio_5min": err_5 / req_5 if req_5 else 0,
        "error_ratio_10min": err_10 / req_10 if req_10 else 0,
        "error_ratio_15min": err_15 / req_15 if req_15 else 0,

        "unique_paths_1min": u_path_1,
        "unique_paths_5min": u_path_5,
        "unique_paths_10min": u_path_10,
        "unique_paths_15min": u_path_15,

        "unique_ext_count_1min": u_ext_1,
        "unique_ext_count_5min": u_ext_5,
        "unique_ext_count_15min": u_ext_15,

        "unique_status_count_1min": u_status_1,
        "unique_status_count_5min": u_status_5,
        "unique_status_count_15min": u_status_15,

        "time_diff_prev_request": time_diff,
    }
