import logging
import re
import subprocess
import sys
import requests
import m3u8
import os
import concurrent.futures
import threading
import time
from Crypto.Cipher import AES
import argparse

class m3u8_downloder:
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        # "Accept-Encoding": "gzip, deflate, br",  # cause result is gzip
        'Accept-Language': 'en-US,en;q=0.9',
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36"
    }
    max_try_count = 20
    cipher = None
    def __init__(self, threads=6, proxies={}, progress_bar=True, logger=logging.getLogger('m3u8_dl')):
        '''
        thread: download ts threads
        max_bitrate: True: select max_bitrate, False: select minbitrate
        '''
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.proxies.update(proxies)

        #helper
        self.m3u8_url_base = ''
        self.cache_path_uuid = ''

        #prograss bar
        self.progress_bar = progress_bar
        self.percent = 0.0
        self.speed = 0 # KB/s
        self.done = [0]*self.threads
        self.byte = [0]*self.threads
        
        self.logger = logger

    def get(self, url, **kwargs):
        try_count = self.max_try_count
        success = True
        while True:
            try:
                response = self.session.get(url, **kwargs)
                if response.status_code != 200:     #maybe site detected too quickly download
                    try_count -= 1
                    if try_count==0:
                        self.logger.warning(f"\nGET {url} exceed max retry times {response.status_code}")
                        success = False
                        break
                    continue
                break
            except:
                try_count -= 1
                if try_count==0:
                    self.logger.warning(f"\nGET {url} got exception")
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    print("Exception type:", exc_type)
                    print("Exception value:", exc_value)
                    print("Exception traceback:", exc_traceback)
                    success = False
                    break
            time.sleep(0.1)
        return response, success

    def run_cmd(self, cmd):
        self.logger.debug(f"run cmd: {cmd}")
        r = subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL)
        return r.returncode

    def get_m3u8_info(self, m3u8_url, select_max_bitrate=True):
        self.logger.debug(f"get m3u8 info: {m3u8_url}")
        response, success = self.get(m3u8_url, timeout=20)
        if not success:
            self.logger.error(f"get m3u8 url failed: {m3u8_url}")
            exit(1)
        m3u8_info = m3u8.loads(response.text)
        
        self.m3u8_url_base = '/'.join(m3u8_url.split('/')[:-1]) + '/'
        if m3u8_info.is_variant: # contains multiple sub m3u8
            self.logger.info(f"m3u8 is variant: {len(m3u8_info.playlists)} total")
            for i, playlist in enumerate(m3u8_info.playlists):
                self.logger.info(f"{i}: {playlist.stream_info.bandwidth} {playlist.uri[:20]}...")
            if select_max_bitrate:
                bitrate_list = [playlist.stream_info.bandwidth for playlist in m3u8_info.playlists]
                playlist_sel = m3u8_info.playlists[bitrate_list.index(max(bitrate_list))]
                self.logger.info(f"select max bitrate: {playlist_sel.stream_info.bandwidth}")
            else: # interactive select
                select = int(input("select: "))
                playlist_sel = m3u8_info.playlists[select]

            # request again
            return self.get_m3u8_info(self.m3u8_url_base + playlist_sel.uri)
        
        m3u8_path = os.path.join(self.cache_path_uuid, "index.m3u8")
        with open(m3u8_path, "w", encoding='utf-8') as fp:
            fp.write(response.text)
        self.logger.debug(f"save m3u8: {m3u8_path}")
        return m3u8_info

    def get_key(self, m3u8_info):
        self.logger.info(f"m3u8 is encrypted")
        
        if self.recover_mode:
            key_path = os.path.join(self.cache_path_uuid, 'key')
            if os.path.exists(key_path):
                with open(key_path, "rb") as fp:
                    key_bytes = fp.read(16)
                    iv = fp.read(16)
                self.cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
                self.logger.debug(f"read key, key len: {len(key_bytes)} \nkey: {key_bytes} \niv: {iv}")
                return
            else:
                self.logger.warning(f"key not found, try to download")
        
        key = m3u8_info.keys[0]
        if key.method != "AES-128":
            self.logger.error(f"{key.method} not supported(only AES-128)")
            exit(1)
        key_url = key.uri
        if not key_url.startswith("http"):
            key_url = self.m3u8_url_base + key_url
        
        self.logger.info(f"download key: {key_url}")
        response, _ = self.get(key_url)
        key_bytes = response.content
        iv = key_bytes
        
        if key.iv is not None:
            # hex string
            if key.iv.startswith('0x'): #0x9102194531bb4f6cad45ad87c3bd8399
                s = key.iv[2:]
                byte_list = []
                for i in range(0, 32, 2):
                    byte_list.append(int(s[i:i+2], base=16))
                iv = bytes(byte_list)
            # bytes
            else:
                iv = key.iv
            self.cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        else:
            self.cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        
        #save key
        key_path = os.path.join(self.cache_path_uuid, 'key')
        with open(key_path, "wb") as fp:
            fp.write(key_bytes)
            fp.write(iv)
        self.logger.debug(f"save key, key len: {len(key_bytes)} \nkey: {key_bytes} \niv: {iv}")

    def get_uuid(self, name):
        # h = hashlib.sha224(name.encode('utf-8')).hexdigest()
        h = re.sub(r'[\\/:*?"<>|]', '_', name)
        return h
    def mk_cache_path_uuid(self, name, cache_path):
        self.recover_mode = False
        #mk unique ts cache path
        h = self.get_uuid(name)
        self.cache_path_uuid = os.path.join(cache_path, h)
        if os.path.exists(self.cache_path_uuid):
            self.recover_mode = True
            self.logger.info(f"recover mode, found cache in {self.cache_path_uuid}")
        else:
            os.mkdir(self.cache_path_uuid)

    def get_ts_urls(self, m3u8_info):
        ts_urls = {} # file, uri
        for i, playlist in enumerate(m3u8_info.segments):
            ts = f"{i:0>8d}.ts"
            ts_urls[ts] = self.m3u8_url_base + playlist.uri
        
        return ts_urls
    
    def get_miss_ts_urls(self, ts_urls):
        miss_ts_urls = {}
        for ts in ts_urls.keys():
            ts_path = os.path.join(self.cache_path_uuid, ts)
            if not os.path.exists(ts_path):
                miss_ts_urls[ts] = ts_urls[ts]
        return miss_ts_urls

    def download_ts(self, ts_urls):
        def download(ts, ts_url):
            tid = int(threading.current_thread().name.split('_')[-1]) #ThreadPoolExecutor-0_2
            response, success = self.get(ts_url, stream=True)
            if success == False:
                self.logger.warning(f"{ts} download failed. Skip")
                self.done[tid] += 1  # still add 1, so that progress bar can reach 100% and exit loop
                return
            
            ts_path = os.path.join(self.cache_path_uuid, ts)
            with open(ts_path, "wb+") as fp:
                for chunk in response.iter_content(chunk_size=8192):
                    fp.write(chunk)
                    self.byte[tid] += len(chunk)
            self.done[tid] += 1

        #multi-threading
        start_time = time.time()
        total = len(ts_urls)            #number of ts segment
        self.done = [0]*self.threads
        done = sum(self.done)           #downloaded ts number
        self.byte = [0]*self.threads    
        byte = byte_pre = sum(self.byte)#downloaded bytes
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            for ts, ts_url in ts_urls.items():
                executor.submit(download, ts, ts_url)
            while done<total:
                done = sum(self.done)
                percent = done/total
                bar1 = int(percent*100)
                bar2 = 100-bar1
                time.sleep(1)
                byte = sum(self.byte)
                delta = byte - byte_pre
                byte_pre = byte
                cur_time = time.time()
                elapsed_time = cur_time - start_time
                remain_time = elapsed_time*(total-done)/done if done!=0 else 1e10
                human_time = time.strftime("%H:%M:%S", time.gmtime(remain_time))
                
                self.percent = percent
                self.speed = delta/1024
                if self.progress_bar:
                    print(f"\r{done:>4d}/{total:<4d}:{bar1*'■'}{bar2*'□'}:{percent:.2%} {delta/1024:>8.0f}KB/s, remain: {human_time}", flush=True, end='')
        end_time = time.time()
        print(f'\navg speed{byte/(end_time-start_time)/1024:>8.0f}KB/s')

    def new_merge(self, ts_files, download_path, filename, format='mkv'):
        # ts_paths = [os.path.join(self.cache_path_uuid, ts) for ts in ts_urls.keys()]
        ts_paths = [os.path.join(self.cache_path_uuid, ts) for ts in ts_files]
        ts_paths.sort() # increase order
        ts_files_path = os.path.join(self.cache_path_uuid, "ts_files.txt")
        with open(ts_files_path, "w") as f:
            for ts_file in ts_files:
                f.write(f"file '{ts_file}'\n")
        
        filepath = os.path.join(download_path, f"{filename}.{format}")
        self.logger.info(f"merge ts in {self.cache_path_uuid} to {filepath}")
        cmd = f"ffmpeg -hide_banner -y -f concat -safe 0 -i {ts_files_path} -c copy {filepath}"
        return_code = self.run_cmd(cmd)
        if return_code != 0:
            self.logger.error(f"merge failed: {filepath}")
            exit(1)
    
    def get_progress(self):
        return f'{self.percent*100:.0f}% {self.speed:.0f} KB/s'

    def remove_cache(self):
        self.run_cmd(f"rm -rf {self.cache_path_uuid}")
        
        # remove cache dir if empty
        cache_dir = os.path.dirname(self.cache_path_uuid)
        file_list = os.listdir(cache_dir)
        if len(file_list)==0:
            self.run_cmd(f"rm -rf {cache_dir}")
        self.logger.info(f"clean cache")
    
    def download(self, m3u8_url, filename, ext, download_path='./', cache_path='./cache',\
        keep_cache=False, select_max_bitrate=True):
        self.logger.info(f"download {m3u8_url} to {download_path}/{filename}.mp4")
        #mkdir
        if not os.path.exists(cache_path):
            os.mkdir(cache_path)
        if not os.path.exists(download_path):
            self.logger.error(f"download path {download_path} not exist, exit")
            exit(1)
        #uuid cache path
        self.mk_cache_path_uuid(filename, cache_path)

        #get m3u8 info
        m3u8_info = self.get_m3u8_info(m3u8_url, select_max_bitrate=select_max_bitrate)
        
        #get ts url
        ts_urls = self.get_ts_urls(m3u8_info)
        self.logger.info(f"{len(ts_urls)} ts segments")

        #if encrypted, get key
        if len(m3u8_info.keys)!=0 and m3u8_info.keys[0] is not None:
            self.get_key(m3u8_info)

        #download ts
        #if recover, get missed ts
        miss_ts_urls = ts_urls
        if self.recover_mode:
            miss_ts_urls = self.get_miss_ts_urls(ts_urls)
        self.logger.info(f"{len(miss_ts_urls)} ts segments need to download")
        
        self.download_ts(miss_ts_urls)
        self.logger.info(f"download ts finish: {self.cache_path_uuid}")
        
        # new merege
        ts_files = ts_urls.keys()
        self.new_merge(ts_files, download_path, filename, format=ext)
        
        #remove cache
        if not keep_cache:
            self.remove_cache()

    def force_merge(self, filename, download_path='./', cache_path='./cache', ext="mkv", keep_cache=False):
        self.cache_path_uuid = os.path.join(cache_path, self.get_uuid(filename))
        if not os.path.exists(self.cache_path_uuid):
            self.logger.error(f"cache path {self.cache_path_uuid} not exist, exit")
            exit(1)
        
        files = os.listdir(self.cache_path_uuid)
        ts_files = [ts for ts in files if ts.endswith('.ts')]
        
        self.new_merge(ts_files, download_path, filename, format=ext)
        
        #remove cache
        if not keep_cache:
            self.remove_cache()

def get_logger(name, level=logging.INFO, filename="", overwrite=False, format='[%(asctime)s][%(levelname)-7s] - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False # forbid print to root logger
    if filename is None or filename == "":
        file_handler = logging.StreamHandler(sys.stdout)
    else:
        if overwrite:
            file_handler = logging.FileHandler(filename, mode='w')
        else:
            file_handler = logging.FileHandler(filename)
    formatter = logging.Formatter(format, datefmt=datefmt)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger

if __name__=="__main__":
    parser = argparse.ArgumentParser(description='m3u8 downloader.')
    parser.add_argument('-u', '--m3u8-url',
                    required=True,
                    default="https://playertest.longtailvideo.com/adaptive/oceans_aes/oceans_aes.m3u8",
                    help='m3u8 url')
    parser.add_argument('-o', '--output',
                    required=True,
                    help='video output path')
    parser.add_argument('-P', '--proxy-url',
                    # default="http://localhost:11223",
                    default="",
                    help='proxy url, support http and socks5(TODO)')
    parser.add_argument('-n', '--thread-num',
                    type=int,
                    default=6,
                    help='download thread number')
    parser.add_argument('-i', '--interactive',
                    action='store_true',
                    help='select variant m3u8 interactively, default select max bitrate video to download')
    parser.add_argument('-v', '--verbose',
                    action='store_true',
                    help='Verbose mode, print debug')
    parser.add_argument('-k', '--keep-cache',
                    action='store_true',
                    help='don;t remove cache dir after merge')
    parser.add_argument('-F', '--force-merge',
                action='store_true',
                help='force merge the ts in cache dir')
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO)  # set root logger
    logger = get_logger('m3u8_dl', level=logging.DEBUG if args.verbose else logging.INFO, format='[%(asctime)s][%(levelname)-7s] - %(name)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    
    if args.proxy_url=="": #no proxy
        proxies = {}
    else:
        proxies = {
            'http': args.proxy_url,
            'https': args.proxy_url
        }
    
    downloader = m3u8_downloder(threads=args.thread_num, proxies=proxies, logger=logger)
    
    video_output_dir = os.path.dirname(args.output)
    if video_output_dir=="":
        video_output_dir = "."
    video_file = os.path.basename(args.output)
    video_filename = video_file.split('.')[0]
    ext = video_file.split('.')[-1].lower()
    supported_format = ['mp4', 'mkv']
    if ext not in supported_format:
        logger.error(f"{ext} not supported, supported format: {supported_format}")
        exit(1)
    download_path = video_output_dir
    cache_path = os.path.join(download_path, "cache")
    if args.force_merge:
        downloader.force_merge(video_filename, download_path=download_path, cache_path=cache_path, ext=ext, keep_cache=args.keep_cache)
        exit(0)
    downloader.download(args.m3u8_url, video_filename, download_path=download_path, cache_path=cache_path, ext=ext,\
        keep_cache=args.keep_cache, select_max_bitrate=not args.interactive)

    