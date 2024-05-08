import sys
import requests
import m3u8
#from . import m3u8
import os
import concurrent.futures
import threading
import time
from Crypto.Cipher import AES
import hashlib
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
    def __init__(self, threads=6, max_bitrate=False, DEBUG=False, proxies={}, progress_bar=True):
        '''
        thread: download ts threads
        max_bitrate: True: select max_bitrate, False: select minbitrate
        '''
        self.threads = threads
        self.max_bitrate = max_bitrate
        self.DEBUG = DEBUG
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
        
        self.log_out = sys.stdout
        self.log_err = sys.stderr

    def log(self, level, *args):
        if level==3 and not self.DEBUG:
            return
        prompt = ["Error", "Warning", "Info", "Debug"]
        if level==0 or level==1: #ERROR or WARNING
            print(f"[{prompt[level]:>7s}]:", *args, file=self.log_err)
        else:
            print(f"[{prompt[level]:>7s}]:", *args, file=self.log_out)

    def get(self, url, **kwargs):
        try_count = self.max_try_count
        succeed = True
        while True:
            try:
                response = self.session.get(url, **kwargs)
                if response.status_code != 200:     #maybe site detected too quickly download
                    try_count -= 1
                    if try_count==0:
                        self.log(1, f"GET {url} exceed max retry times{response.status_code}")
                        succeed = False
                        break
                    continue
                break
            except:
                try_count -= 1
                if try_count==0:
                    self.log(1, f"GET {url}", sys.exc_info()[0])
                    succeed = False
                    break
        return response, succeed

    def run_cmd(self, cmd):
        if self.DEBUG:
            self.log(3, "OS:", cmd)
        p = os.popen(cmd)
        output = p.read()

    def get_m3u8_info(self, m3u8_url):
        self.log(3, f"GET {m3u8_url}")
        response, _ = self.get(m3u8_url, timeout=20)
        m3u8_info = m3u8.loads(response.text)
        
        self.m3u8_url_base = '/'.join(m3u8_url.split('/')[:-1]) + '/'
        if m3u8_info.is_variant:
            self.log(3, f"m3u8 is variant: {len(m3u8_info.playlists)} total")
            # select max bitrate m3u8
            max_bitrate = m3u8_info.playlists[0].stream_info.bandwidth
            max_playlist = m3u8_info.playlists[0]
            for playlist in m3u8_info.playlists[1:]:
                if self.max_bitrate:
                    if playlist.stream_info.bandwidth > max_bitrate:
                        max_bitrate = playlist.stream_info.bandwidth
                        max_playlist = playlist
                else:
                    if playlist.stream_info.bandwidth < max_bitrate:
                        max_bitrate = playlist.stream_info.bandwidth
                        max_playlist = playlist
            self.log(3, f"select bitrate: {max_bitrate}")
            # request again
            return self.get_m3u8_info(self.m3u8_url_base + max_playlist.uri)
        
        m3u8_path = os.path.join(self.cache_path_uuid, "index.m3u8")
        with open(m3u8_path, "w", encoding='utf-8') as fp:
            fp.write(response.text)
        # self.log(2, f"save m3u8: {m3u8_path}")
        return m3u8_info

    def get_key(self, m3u8_info):
        self.log(2, f"m3u8 is encrypted")
        
        if self.recover_mode:
            key_path = os.path.join(self.cache_path_uuid, 'key')
            if os.path.exists(key_path):
                with open(key_path, "rb") as fp:
                    key_bytes = fp.read(16)
                    iv = fp.read(16)
                self.cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
                self.log(3, f"read key, key:", len(key_bytes), key_bytes, "iv:", iv)
                return
            else:
                self.log(2, f"key not found, try to download")
        
        key = m3u8_info.keys[0]
        if key.method != "AES-128":
            self.log(0, f"{key.method} not supported(only AES-128)")
            exit(-1)
        key_url = key.uri
        if not key_url.startswith("http"):
            key_url = self.m3u8_url_base + key_url
        
        self.log(2, f"download key: {key_url}")
        response, _ = self.get(key_url)
        key_bytes = response.content
        iv = key_bytes
        
        if key.iv is not None:
            if key.iv.startswith('0x'): #0x9102194531bb4f6cad45ad87c3bd8399
                s = key.iv[2:]
                byte_list = []
                for i in range(0, 32, 2):
                    byte_list.append(int(s[i:i+2], base=16))
                iv = bytes(byte_list)
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
        self.log(3, f"write key, key:", len(key_bytes), key_bytes, "iv:", iv)

    def mk_cache_path_uuid(self, name, cache_path):
        self.recover_mode = False
        #mk unique ts cache path
        h = hashlib.sha224(name.encode('utf-8')).hexdigest()
        self.cache_path_uuid = os.path.join(cache_path, h)
        if os.path.exists(self.cache_path_uuid):
            self.recover_mode = True
            self.log(2, "recover mode")
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
            # self.log(3, tid, ts)
            response, succeed = self.get(ts_url, stream=True)
            if succeed == False:
                self.log(0, f"{ts} download failed")
                self.done[tid] += 1
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
                
                self.percent = percent
                self.speed = delta/1024
                if self.progress_bar:
                    print(f"\r{done:>4d}/{total:<4d}:{bar1*'■'}{bar2*'□'}:{percent:.2%} {delta/1024:>8.0f}KB/s", flush=True, end='')
        end_time = time.time()
        self.log(2, f'avg speed{byte/(end_time-start_time)/1024:>8.0f}KB/s')

    def merge_ts(self, ts_urls):
        output_flv = os.path.join(self.cache_path_uuid, "cache.flv")
        out = open(output_flv, "wb+")
        for ts in ts_urls.keys():
            ts_path = os.path.join(self.cache_path_uuid, ts)
            try:
                with open(ts_path, "rb") as fp:
                    content = fp.read()
                    # content += b'\0'*((16 - len(content)%16)%16)
                    if self.cipher is None:
                        out.write(content)
                    else:
                        out.write(self.cipher.decrypt(content))
            except:
                self.log(0, f"merge failed: {ts} miss")
                exit(-1)
        out.close()
        return output_flv
    
    def get_progress(self):
        return f'{self.percent*100:.0f}% {self.speed:.0f} KB/s'

    def download(self, m3u8_url, name, download_path='./', cache_path='./cache'):
        #mkdir
        if not os.path.exists(cache_path):
            os.mkdir(cache_path)
        if not os.path.exists(download_path):
            print(f"download path {download_path} not exist")
            exit(1)
        #uuid cache path
        self.mk_cache_path_uuid(name, cache_path)
        #err log
        self.log_err = open(os.path.join(self.cache_path_uuid, "error.log"), "w", encoding='utf-8')

        #get m3u8 info
        m3u8_info = self.get_m3u8_info(m3u8_url)
        
        #get ts url
        ts_urls = self.get_ts_urls(m3u8_info)
        self.log(2, f"{len(ts_urls)} ts segments")

        #if encrypted, get key
        if len(m3u8_info.keys)!=0 and m3u8_info.keys[0] is not None:
            self.get_key(m3u8_info)

        #download ts
        #if recover, get missed ts
        miss_ts_urls = ts_urls
        if self.recover_mode:
            miss_ts_urls = self.get_miss_ts_urls(ts_urls)
        self.log(2, f"{len(miss_ts_urls)} missed ts segments")
        
        self.download_ts(miss_ts_urls)
        self.log(2, f"download ts finish: {self.cache_path_uuid}")
        
        #merge ts to flv
        output_flv = self.merge_ts(ts_urls)
        self.log(2, f"merge ts to flv: {output_flv}")

        #convert to mp4
        output_mp4 = os.path.join(download_path, name+".mp4")
        log = os.path.join(self.cache_path_uuid, "ffmpeg_error.log")
        self.run_cmd(f"ffmpeg -y -i {output_flv} -c copy \"{output_mp4}\" > {log} 2>&1")
        self.log(2, f"ffmpeg convert flv to mp4: {output_mp4}")

        #remove cache
        self.run_cmd(f"rm -rf {output_flv}")
        self.run_cmd(f"rm -rf {self.cache_path_uuid}")
        self.log(2, f"clean cache")
        
        self.log_err.close()

    def force_merge(self, cache_path_uuid, download_path='./', name="force_merge"):
        def get_files_under_dir(dir):
            '''获得dir目录下的所有文件
            '''
            for f in os.listdir(dir):
                if os.path.isfile(os.path.join(dir, f)):
                    yield f
        self.cache_path_uuid = cache_path_uuid
        self.recover_mode = True
        self.get_key(None)

        ts_urls = {}
        files = get_files_under_dir(cache_path_uuid)
        i = 0
        for f in files:
            if f.split('.')[-1]=="ts":
                ts = f"{i:0>8d}.ts"
                ts_urls[ts] = ""    #only care dict key
                i += 1
        self.log(2, f"ts count: {i}")
        #merge ts to flv
        output_flv = self.merge_ts(ts_urls)
        self.log(2, f"merge ts to flv: {output_flv}")

        #convert to mp4
        output_mp4 = os.path.join(download_path, name+".mp4")
        self.run_cmd(f"ffmpeg -y -i {output_flv} -c copy \"{output_mp4}\"")
        self.log(2, f"ffmpeg convert flv to mp4: {output_mp4}")

if __name__=="__main__":
    parser = argparse.ArgumentParser(description='m3u8 downloader：下载m3u8视频，并转换成mp4。1）支持多线程加速下载ts 2）支持variant m3u8 3）支持AES-128加密 4）支持显示进度条，网速 5）支持自动恢复下载 6）支持代理'
                                     )
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
    parser.add_argument('-m', '--max-bitrate',
                    action='store_true',
                    help='select max bitrate')
    parser.add_argument('-v', '--verbose',
                    action='store_true',
                    help='Verbose mode, print debug')
    args = parser.parse_args()
    
    if args.proxy_url=="": #no proxy
        proxies = {}
    else:
        proxies = {
            'http': args.proxy_url,
            'https': args.proxy_url
        }
    
    downloader = m3u8_downloder(threads=args.thread_num, max_bitrate=True, DEBUG=args.verbose, proxies=proxies)
    
    video_output_dir = os.path.dirname(args.output)
    if video_output_dir=="":
        video_output_dir = "."
    video_filename = os.path.basename(args.output)
    download_path = video_output_dir
    cache_path = os.path.join(download_path, "cache")
    downloader.download(args.m3u8_url, video_filename, download_path=download_path, cache_path=cache_path)

# if __name__=="__main__":
#     '''降cache_path下第一个找到的目录中的ts合并成mp4，保存在当前目录。name指定名称
#     '''
#     cache_path_uuid = sys.argv[1]

#     downloader = m3u8_downloder(threads=6, max_bitrate=True, DEBUG=True, proxies={})
#     downloader.force_merge(cache_path_uuid)


