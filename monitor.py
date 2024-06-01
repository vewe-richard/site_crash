import os
import psutil
import time
import datetime
import logging


# Monitor the system, and in case of below situation
# 1. free memory < 200M
# 2. cache memory < 100M
# 3. cpu percent > 80% for 5 seconds
# Then the monitor will kill the recent processes(not kernel processes), which cpu usage > 10% 
# or memory usage > 200M

# Configuration
MB = 1024*1024
ALERT_FREE_MEMORY = 200*MB
ALERT_CACHE_MEMORY = 100*MB
ALERT_CPU_PERCENT = 80  #80%
ALERT_CPU_OVERLOAD_LAST = 5

SUSPICIOUS_MEMORY = 200*MB
SUSPICIOUS_CPU_PERCENT = 30 #10%
SUSPICIOUS_RUN_TIME = 30*60

SUSPICIOUS_KILLED = False


logging.basicConfig(filename='log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Get system memory information
psutil.cpu_percent()
for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'create_time']):
        p.cpu_percent(interval=None)

time.sleep(1)

cpu_overloading = 0
while True:
    current_time = datetime.datetime.now()
    mem = psutil.virtual_memory()
    free_memory = mem.available
    cache_memory = mem.cached
    cpu_percent = psutil.cpu_percent()
    logging.info(f"free {free_memory/MB}, cache {cache_memory/MB}, cpu loading {cpu_percent}%")
    alert = False
    if free_memory < ALERT_FREE_MEMORY or cache_memory < ALERT_CACHE_MEMORY:
        logging.warning(f"memory alert")
        alert = True

    if cpu_percent > ALERT_CPU_PERCENT:
        logging.warning(f"cpu overloading times:{cpu_overloading}")
        cpu_overloading += 1
    else:
        cpu_overloading = 0

    if cpu_overloading > ALERT_CPU_OVERLOAD_LAST:
        logging.warning(f"cpu loading alert")
        alert = True

    for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'create_time']):
        if p.info['pid'] == os.getpid():
            continue
        meminfo = p.info['memory_info']
        percent = p.info['cpu_percent']

        if meminfo.rss > SUSPICIOUS_MEMORY or percent > SUSPICIOUS_CPU_PERCENT:
            create_time = datetime.datetime.fromtimestamp(p.info['create_time'])
            time_passed = current_time - create_time
            logging.info(f"{p.name()}({time_passed.total_seconds()}): {meminfo.rss/MB}MB cpu {percent}")
            if p.name()[0] == 'k':
                continue
            if time_passed.total_seconds() > SUSPICIOUS_RUN_TIME: #only killed recent test application
                continue
            logging.warning(f"suspicious process: {p.name()} \n{p}{meminfo}")

            if alert and SUSPICIOUS_KILLED:
                target_process = psutil.Process(p.info['pid'])
                parent_pid = target_process.ppid()

                target_process.kill()
                if parent_pid > 100:
                    parent = psutil.Process(parent_pid)
                    parent.kill()
                #target_process.terminate()
                logging.info(f"Process killed {p.name()}, pid{p.info['pid']}")





    time.sleep(1)
