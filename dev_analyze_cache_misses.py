import re
import sys

def analyze_log(log_path):
    print(f"Analyzing: {log_path}")
    
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading log: {e}")
        return

    # Patterns
    p_open = re.compile(r"FastVFS: Open\(\) URL: (.*)")
    p_read_req = re.compile(r"FastVFS: Read\(\) 请求 (\d+) bytes \(Pos: (\d+)\)")
    p_read_hit = re.compile(r"FastVFS: Read 完全命中.*Pos: (\d+)")
    p_lazy_init = re.compile(r"FastVFS: \[Lazy Init\]")
    p_miss_lag = re.compile(r"FastVFS: Read 落后")
    p_miss_far = re.compile(r"FastVFS: Read 超前")
    p_preload_dl = re.compile(r"FastVFS: \[预热\] 开始下载")
    p_preload_hit = re.compile(r"FastVFS: \[预热\] 全局缓存命中")

    # State
    last_read = None # (line_num, size, pos, full_line_text)
    
    print("-" * 60)
    
    for i, line in enumerate(lines):
        line = line.strip()
        
        # 1. Open
        m_open = p_open.search(line)
        if m_open:
            # print(f"\n[Line {i+1}] OPEN FILE: {m_open.group(1)}")
            last_read = None
            continue

        # 2. Lazy Init (Major Penetration Event)
        if p_lazy_init.search(line):
            print(f"[Line {i+1}] \033[91m--> RING BUFFER STARTUP (Lazy Init)\033[0m")
            continue

        # 3. Explicit Misses (Reconnects)
        if p_miss_lag.search(line) or p_miss_far.search(line):
             print(f"[Line {i+1}] \033[91m--> CACHE MISS (Reconnect): {line}\033[0m")
             continue

        # 4. Preload Downloads (Network Activity)
        if p_preload_dl.search(line):
             print(f"[Line {i+1}] --> Preload Downloading (Network Active)")
             continue
             
        # Resets
        if "FastVFS: 调用 Close()" in line:
            if last_read:
                print(f"[Line {last_read[0]}] \033[93m--> CACHE PENETRATION (RingBuffer Read): Size {last_read[1]} @ {last_read[2]}\033[0m")
                last_read = None
            # print(f"[Line {i+1}] CLOSE FILE")
            continue

        # 5. Read Request
        m_req = p_read_req.search(line)
        if m_req:
            # If there was a previous read pending that wasn't marked as hit, report it now
            if last_read:
                 print(f"[Line {last_read[0]}] \033[93m--> CACHE PENETRATION (RingBuffer Read): Size {last_read[1]} @ {last_read[2]}\033[0m")
            
            size = m_req.group(1)
            pos = m_req.group(2)
            last_read = (i+1, size, pos, line)
            continue

        # 6. Read Hit
        m_hit = p_read_hit.search(line)
        if m_hit:
            hit_pos = m_hit.group(1)
            if last_read:
                # Check if this hit corresponds to the last request
                # (Simple pos check is usually enough as simple VFS is blocking)
                if last_read[2] == hit_pos:
                    # It was a hit, so ignore the pending read
                    # print(f"[Line {last_read[0]}] (Cache Hit detected)")
                    last_read = None
                else:
                    # Weird mismatch?
                    pass
            continue

    # Flush last
    if last_read:
        print(f"[Line {last_read[0]}] \033[93m--> CACHE PENETRATION (RingBuffer Read): Size {last_read[1]} @ {last_read[2]}\033[0m")

if __name__ == "__main__":
    # Default path based on your environment
    log_path = r"c:\Users\31537\AppData\Local\Packages\XBMCFoundation.Kodi_4n2hpmxwrvr6p\LocalCache\Roaming\Kodi\kodi.log"
    
    # Allow command line argument override
    if len(sys.argv) > 1:
        log_path = sys.argv[1]
    
    analyze_log(log_path)
