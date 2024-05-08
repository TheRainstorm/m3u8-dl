## description

yet another m3u8 downloader.

features:

- support multi-thread download
- support variant m3u8
- support AES-128 encryption
- support showing progress bar, network speed
- support recovering failed download
- support setting network proxy

## Usage

### install dependencies

```shell
pip install -r requirements.txt

sudo apt install ffmpeg
```

get some m3u8 url to test [site](https://livepush.io/hls-player/index.html)

### run

```shell
usage: m3u8_dl.py [-h] -u M3U8_URL -o OUTPUT [-P PROXY_URL] [-n THREAD_NUM] [-i] [-v] [-k] [-F]

m3u8 downloader.

options:
  -h, --help            show this help message and exit
  -u M3U8_URL, --m3u8-url M3U8_URL
                        m3u8 url
  -o OUTPUT, --output OUTPUT
                        video output path
  -P PROXY_URL, --proxy-url PROXY_URL
                        proxy url, support http and socks5(TODO)
  -n THREAD_NUM, --thread-num THREAD_NUM
                        download thread number
  -i, --interactive     select variant m3u8 interactively, default select max bitrate video to download
  -v, --verbose         Verbose mode, print debug
  -k, --keep-cache      don;t remove cache dir after merge
  -F, --force-merge     force merge the ts in cache dir
```

example:

```shell
python m3u8_dl.py -u https://live-par-2-cdn-alt.livepush.io/live/bigbuckbunnyclip/index.m3u8 -o test.mkv

# change destination directory
python m3u8_dl.py -u https://live-par-2-cdn-alt.livepush.io/live/bigbuckbunnyclip/index.m3u8 -o /mnt/Disk1/test.mkv

# select video interactive if m3u8 if variant
python m3u8_dl.py -u https://live-par-2-cdn-alt.livepush.io/live/bigbuckbunnyclip/index.m3u8 -o /mnt/Disk1/test.mkv -i
```
